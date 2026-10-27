use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};

pub const LABEL: &str = "local.agent-bridge";
pub fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}
pub fn default_state_dir() -> Result<PathBuf> {
    Ok(home()?.join("Library/Application Support/AgentBridge"))
}
pub fn installed_binary() -> Result<PathBuf> {
    Ok(home()?.join(".local/bin/agent-bridge"))
}
pub fn find_binary(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|p| p.join(name))
        .find(|p| p.is_file())
}
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    let temp = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

fn atomic_copy(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    let temporary = destination.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut input = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(source)?;
        ensure!(
            input.metadata()?.is_file(),
            "Only regular files can be copied"
        );
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        std::fs::rename(&temporary, destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}

pub fn plist(binary: &Path, state: &Path, _codex: &Path) -> String {
    let args = [
        binary.to_string_lossy().into_owned(),
        "--state-dir".into(),
        state.to_string_lossy().into_owned(),
        "serve".into(),
    ];
    let args = args
        .iter()
        .map(|a| format!("<string>{}</string>", xml(a)))
        .collect::<String>();
    let path = format!(
        "{}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        home().unwrap_or_default().join(".local/bin").display()
    );
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{LABEL}</string>\n<key>ProgramArguments</key><array>{args}</array>\n<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n<key>ThrottleInterval</key><integer>10</integer>\n<key>Umask</key><integer>63</integer>\n<key>EnvironmentVariables</key><dict><key>PATH</key><string>{}</string></dict>\n<key>StandardOutPath</key><string>{}</string>\n<key>StandardErrorPath</key><string>{}</string>\n</dict></plist>\n",
        xml(&path),
        xml(&state.join("service.stdout.log").to_string_lossy()),
        xml(&state.join("service.stderr.log").to_string_lossy())
    )
}

fn domain() -> String {
    format!("gui/{}", unsafe { libc::geteuid() })
}

fn text_path(path: &Path) -> Result<&str> {
    let value = path.to_str().context("Service paths must be UTF-8")?;
    ensure!(
        path.is_absolute() && !value.chars().any(char::is_control),
        "Service paths must be absolute and contain no control characters"
    );
    Ok(value)
}
fn unit_quote(value: &str, dollars: bool) -> Result<String> {
    ensure!(
        !value.chars().any(char::is_control),
        "Service values cannot contain control characters"
    );
    let mut result = String::from("\"");
    for c in value.chars() {
        match c {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '%' => result.push_str("%%"),
            '$' if dollars => result.push_str("$$"),
            other => result.push(other),
        }
    }
    result.push('"');
    Ok(result)
}
/// Render a per-user unit without involving a shell or expanding path specifiers.
pub fn systemd_unit(
    binary: &Path,
    state: &Path,
    user_home: &Path,
    codex_home: Option<&Path>,
) -> Result<String> {
    let executable = unit_quote(text_path(binary)?, true)?;
    let state = unit_quote(text_path(state)?, true)?;
    let path = format!(
        "{}:/usr/local/bin:/usr/bin:/bin",
        text_path(&user_home.join(".local/bin"))?
    );
    let mut environment = format!(
        "Environment={}\n",
        unit_quote(&format!("PATH={path}"), false)?
    );
    if let Some(home) = codex_home {
        environment.push_str(&format!(
            "Environment={}\n",
            unit_quote(&format!("CODEX_HOME={}", text_path(home)?), false)?
        ));
    }
    Ok(format!(
        "[Unit]\nDescription=Agent Bridge local session messaging\nAfter=default.target\n\n[Service]\nType=simple\nExecStart={executable} --state-dir {state} serve\n{environment}UMask=0077\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n"
    ))
}

#[derive(Clone, Copy)]
enum Kind {
    Linux,
    Mac,
}
struct Manager {
    kind: Kind,
    program: PathBuf,
}
impl Manager {
    fn native() -> Result<Self> {
        if cfg!(target_os = "linux") {
            Ok(Self {
                kind: Kind::Linux,
                program: "systemctl".into(),
            })
        } else if cfg!(target_os = "macos") {
            Ok(Self {
                kind: Kind::Mac,
                program: "launchctl".into(),
            })
        } else {
            anyhow::bail!(
                "User services support Linux/systemd and macOS/launchd; run agent-bridge serve manually"
            )
        }
    }
    fn output(&self, args: &[&str]) -> Result<Output> {
        Command::new(&self.program).args(args).output().context("Cannot contact the user service manager; use installer --no-service and run agent-bridge serve manually")
    }
    fn checked(&self, args: &[&str]) -> Result<()> {
        let out = self.output(args)?;
        ensure!(
            out.status.success(),
            "User service manager rejected {}; inspect your user service configuration",
            args.join(" ")
        );
        Ok(())
    }
    fn available(&self) -> Result<()> {
        match self.kind{
            Kind::Linux=>self.checked(&["--user","show-environment"]).context("No systemd user session is available; use installer --no-service and run agent-bridge serve manually"),
            Kind::Mac=>self.checked(&["print",&domain()]).context("No graphical launchd user session is available; run agent-bridge serve manually"),
        }
    }
    fn active(&self) -> Result<bool> {
        Ok(match self.kind {
            Kind::Linux => self
                .output(&["--user", "is-active", "--quiet", "agent-bridge.service"])?
                .status
                .success(),
            Kind::Mac => self
                .output(&["print", &format!("{}/{LABEL}", domain())])?
                .status
                .success(),
        })
    }
    fn enabled(&self) -> Result<bool> {
        Ok(match self.kind {
            Kind::Linux => self
                .output(&["--user", "is-enabled", "--quiet", "agent-bridge.service"])?
                .status
                .success(),
            Kind::Mac => true,
        })
    }
    fn stop(&self) -> Result<()> {
        match self.kind {
            Kind::Linux => self.checked(&["--user", "stop", "agent-bridge.service"]),
            Kind::Mac => {
                if self.active()? {
                    self.checked(&["bootout", &format!("{}/{LABEL}", domain())])?;
                }
                let until = Instant::now() + Duration::from_secs(5);
                while self.active()? {
                    ensure!(
                        Instant::now() < until,
                        "launchd did not finish stopping the old service"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(())
            }
        }
    }
    fn reload(&self) -> Result<()> {
        match self.kind {
            Kind::Linux => self.checked(&["--user", "daemon-reload"]),
            Kind::Mac => Ok(()),
        }
    }
    fn set_enabled(&self, enabled: bool) -> Result<()> {
        match self.kind {
            Kind::Linux => self.checked(&[
                "--user",
                if enabled { "enable" } else { "disable" },
                "agent-bridge.service",
            ]),
            Kind::Mac => Ok(()),
        }
    }
    fn start(&self, definition: &Path) -> Result<()> {
        match self.kind {
            Kind::Linux => self.checked(&["--user", "start", "agent-bridge.service"]),
            Kind::Mac => {
                let until = Instant::now() + Duration::from_secs(5);
                loop {
                    if self
                        .output(&["bootstrap", &domain(), text_path(definition)?])?
                        .status
                        .success()
                    {
                        return Ok(());
                    }
                    ensure!(
                        Instant::now() < until,
                        "launchd could not load the service; inspect its private logs"
                    );
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

// Parse only the plain ExecStart forms generated here and the legacy installer.
// Ambiguous custom commands/specifier/env expansion fail closed before stopping.
fn unit_words(input: &str) -> Result<Vec<String>> {
    let mut result = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        ensure!(!c.is_control(), "Control character in service command");
        match c {
            '\\' => {
                let next = chars.next().context("Incomplete service command escape")?;
                let decoded = match next {
                    '\\' | '"' | '\'' => next,
                    's' => ' ',
                    'x' => {
                        let a = chars.next().context("Incomplete service hex escape")?;
                        let b = chars.next().context("Incomplete service hex escape")?;
                        let value = u8::from_str_radix(&format!("{a}{b}"), 16)?;
                        ensure!(
                            (32..127).contains(&value) && value != b'$' && value != b'%',
                            "Unsupported service hex escape"
                        );
                        value as char
                    }
                    _ => anyhow::bail!("Unsupported custom service escape"),
                };
                word.push(decoded);
                started = true;
            }
            '"' | '\'' => {
                if quote == Some(c) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(c);
                } else {
                    word.push(c);
                }
                started = true;
            }
            ' ' if quote.is_none() => {
                if started {
                    result.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            '%' | '$' => {
                ensure!(
                    chars.next() == Some(c),
                    "Custom service expansion is ambiguous; use an explicit absolute --state-dir"
                );
                word.push(c);
                started = true;
            }
            other => {
                word.push(other);
                started = true;
            }
        }
    }
    ensure!(quote.is_none(), "Unclosed quote in service command");
    if started {
        result.push(word);
    }
    Ok(result)
}
fn systemd_arguments(input: &str) -> Result<Vec<String>> {
    let mut section = false;
    let mut commands = Vec::new();
    let mut ambiguous_home = false;
    for line in input.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            section = line == "[Service]";
            continue;
        }
        if !section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key == "ExecStart" {
            if value.is_empty() {
                commands.clear();
            } else {
                commands.push(value);
            }
        }
        if key == "EnvironmentFile" && !value.is_empty() {
            ambiguous_home = true;
        }
        if key == "Environment"
            && value
                .split_whitespace()
                .any(|v| v.trim_start_matches(['\'', '"']).starts_with("HOME="))
        {
            ambiguous_home = true;
        }
        ensure!(
            value.is_empty()
                || ![
                    "RootDirectory",
                    "RootImage",
                    "BindPaths",
                    "BindReadOnlyPaths",
                    "TemporaryFileSystem",
                    "MountImages",
                    "ExtensionImages",
                    "ExtensionDirectories",
                    "User",
                    "PAMName"
                ]
                .contains(&key),
            "Custom service filesystem/user remapping cannot be backed up safely; configure it manually"
        );
    }
    ensure!(
        commands.len() == 1,
        "Cannot determine one unambiguous service ExecStart; configure service manually"
    );
    let arguments = unit_words(commands[0])?;
    ensure!(
        !ambiguous_home || explicit_state(&arguments),
        "Existing service HOME is ambiguous; add an explicit --state-dir to its command before installing"
    );
    Ok(arguments)
}
fn explicit_state(arguments: &[String]) -> bool {
    arguments
        .iter()
        .any(|v| v == "--state-dir" || v.starts_with("--state-dir="))
}
fn validate_arguments(arguments: &[String], paths: &Paths) -> Result<()> {
    ensure!(
        arguments
            .first()
            .is_some_and(|v| Path::new(v) == paths.binary),
        "Existing service uses a different executable; configure it explicitly before installing"
    );
    let mut state = None;
    let mut served = false;
    let mut index = 1;
    while index < arguments.len() {
        let value = &arguments[index];
        match value.as_str() {
            "--state-dir" => {
                ensure!(state.is_none(), "Repeated service state option");
                index += 1;
                state = Some(PathBuf::from(
                    arguments.get(index).context("Missing service state path")?,
                ));
            }
            "--codex-bin" => {
                index += 1;
                ensure!(
                    arguments.get(index).is_some(),
                    "Missing legacy Codex option"
                );
            }
            "serve" => {
                ensure!(!served, "Ambiguous service command");
                served = true;
            }
            "--no-discovery" => {}
            _ if value.starts_with("--state-dir=") => {
                ensure!(state.is_none(), "Repeated service state option");
                state = Some(PathBuf::from(value.strip_prefix("--state-dir=").unwrap()));
            }
            _ => anyhow::bail!(
                "Custom service arguments are ambiguous; configure its explicit --state-dir manually"
            ),
        }
        index += 1;
    }
    ensure!(served, "Existing service does not run agent-bridge serve");
    let state = state.map_or_else(default_state_dir, Ok)?;
    ensure!(
        state.canonicalize()? == paths.state,
        "Existing service uses a different state directory; repeat installation with its exact --state-dir before upgrading"
    );
    Ok(())
}
impl Manager {
    fn validate_definition(&self, paths: &Paths) -> Result<()> {
        let arguments = match self.kind {
            Kind::Linux => {
                let out = self.output(&["--user", "cat", "agent-bridge.service"])?;
                ensure!(
                    out.status.success(),
                    "Cannot inspect effective service definition"
                );
                let arguments = systemd_arguments(std::str::from_utf8(&out.stdout)?)?;
                if !explicit_state(&arguments) {
                    let environment = self.output(&["--user", "show-environment"])?;
                    ensure!(
                        environment.status.success(),
                        "Cannot verify service manager HOME"
                    );
                    let text = std::str::from_utf8(&environment.stdout)?;
                    let native_home = text
                        .lines()
                        .find_map(|line| line.strip_prefix("HOME="))
                        .context(
                            "Service manager HOME is unknown; configure an explicit --state-dir",
                        )?;
                    let native_home = unit_words(native_home)?;
                    ensure!(
                        native_home.len() == 1
                            && Path::new(&native_home[0]).canonicalize()?
                                == home()?.canonicalize()?,
                        "Service manager HOME differs; configure an explicit --state-dir"
                    );
                }
                arguments
            }
            Kind::Mac => {
                let out = Command::new("/usr/bin/plutil")
                    .args(["-convert", "json", "-o", "-"])
                    .arg(&paths.definition)
                    .output()?;
                ensure!(
                    out.status.success(),
                    "Cannot inspect launchd ProgramArguments"
                );
                let plist: serde_json::Value = serde_json::from_slice(&out.stdout)?;
                let arguments =
                    serde_json::from_value::<Vec<String>>(plist["ProgramArguments"].clone())?;
                ensure!(
                    plist.get("BundleProgram").is_none(),
                    "Custom launchd BundleProgram cannot be upgraded safely"
                );
                if let Some(program) = plist.get("Program") {
                    ensure!(
                        program
                            .as_str()
                            .is_some_and(|v| Path::new(v) == paths.binary),
                        "Existing launchd Program uses a different executable"
                    );
                }
                ensure!(
                    plist.get("UserName").is_none(),
                    "Custom launchd user mapping cannot be upgraded safely"
                );
                ensure!(
                    explicit_state(&arguments),
                    "Existing launchd service must have an explicit --state-dir before upgrading"
                );
                ensure!(
                    plist.get("RootDirectory").is_none(),
                    "Custom launchd filesystem remapping cannot be backed up safely"
                );
                arguments
            }
        };
        validate_arguments(&arguments, paths)
    }
}

struct Paths {
    binary: PathBuf,
    state: PathBuf,
    definition: PathBuf,
    backup_root: PathBuf,
}
fn owned_regular(path: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o022 == 0,
        "Refusing a non-regular, writable-by-others or foreign installation file"
    );
    Ok(true)
}
fn lock_file(path: &Path) -> Result<File> {
    use fs2::FileExt;
    use std::os::unix::fs::MetadataExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == unsafe { libc::geteuid() },
        "Installation lock must be a regular file owned by this user"
    );
    file.try_lock_exclusive()
        .context("Another service or installer owns this state; stop the unmanaged broker first")?;
    Ok(file)
}
fn copy_state(source: &Path, destination: &Path, skip_lock: bool) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    crate::broker::private_dir(destination)?;
    for item in std::fs::read_dir(source)? {
        let item = item?;
        let meta = std::fs::symlink_metadata(item.path())?;
        if meta.file_type().is_socket() || (skip_lock && item.file_name() == "service.lock") {
            continue;
        }
        ensure!(
            !meta.file_type().is_symlink() && meta.uid() == unsafe { libc::geteuid() },
            "State backup refuses symlinks and foreign-owned entries"
        );
        let target = destination.join(item.file_name());
        if meta.is_dir() {
            copy_state(&item.path(), &target, false)?;
        } else {
            ensure!(meta.is_file(), "State backup refuses special files");
            atomic_copy(&item.path(), &target, 0o600)?;
        }
    }
    Ok(())
}
fn canonical_future(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut existing = absolute.as_path();
    let mut tail = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(mut resolved) => {
                for component in tail.iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tail.push(
                    existing
                        .file_name()
                        .context("Use a normalized installation path")?
                        .to_os_string(),
                );
                existing = existing
                    .parent()
                    .context("Cannot resolve installation path")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}
fn disjoint_paths(paths: &Paths) -> Result<()> {
    let state = canonical_future(&paths.state)?;
    let backup = canonical_future(&paths.backup_root)?;
    ensure!(
        !state.starts_with(&backup) && !backup.starts_with(&state),
        "State and private backup directories must be disjoint; choose a dedicated --state-dir outside the backup store"
    );
    let install_lock = paths
        .binary
        .parent()
        .context("Missing binary directory")?
        .join(".agent-bridge-install.lock");
    for artifact in [&paths.binary, &paths.definition, &install_lock] {
        let artifact = canonical_future(artifact)?;
        ensure!(
            !artifact.starts_with(&state) && !state.starts_with(&artifact),
            "State must be a dedicated directory separate from installed executable, service definition and installer lock"
        );
    }
    Ok(())
}

struct Backup {
    directory: PathBuf,
    old_binary: bool,
    old_definition: bool,
    was_active: bool,
    was_enabled: bool,
}
impl Backup {
    fn create(paths: &Paths, was_active: bool, was_enabled: bool) -> Result<Self> {
        disjoint_paths(paths)?;
        crate::broker::private_dir(&paths.backup_root)?;
        safe_directory(&paths.backup_root)?;
        let directory = paths.backup_root.join(uuid::Uuid::new_v4().to_string());
        crate::broker::private_dir(&directory)?;
        let old_binary = owned_regular(&paths.binary)?;
        let old_definition = owned_regular(&paths.definition)?;
        if old_binary {
            atomic_copy(&paths.binary, &directory.join("binary"), 0o700)?;
        }
        if old_definition {
            atomic_write(
                &directory.join("service"),
                &std::fs::read(&paths.definition)?,
                0o600,
            )?;
        }
        copy_state(&paths.state, &directory.join("state"), false)?;
        atomic_write(&directory.join("manifest.json"),serde_json::to_vec_pretty(&serde_json::json!({"was_active":was_active,"was_enabled":was_enabled,"had_binary":old_binary,"had_service":old_definition,"state":paths.state,"binary":paths.binary,"service":paths.definition}))?.as_slice(),0o600)?;
        Ok(Self {
            directory,
            old_binary,
            old_definition,
            was_active,
            was_enabled,
        })
    }
    fn restore(&self, paths: &Paths) -> Result<()> {
        // Keep the held service.lock inode in place while restoring. Otherwise an
        // unmanaged broker could acquire a replacement lock during recovery.
        let failed = self.directory.join("failed-state");
        crate::broker::private_dir(&failed)?;
        for item in std::fs::read_dir(&paths.state)? {
            let item = item?;
            if item.file_name() != "service.lock" {
                std::fs::rename(item.path(), failed.join(item.file_name()))?;
            }
        }
        copy_state(&self.directory.join("state"), &paths.state, true)?;
        if self.old_binary {
            atomic_copy(&self.directory.join("binary"), &paths.binary, 0o755)?;
        } else if paths.binary.exists() {
            std::fs::remove_file(&paths.binary)?;
        }
        if self.old_definition {
            atomic_write(
                &paths.definition,
                &std::fs::read(self.directory.join("service"))?,
                0o600,
            )?;
        } else if paths.definition.exists() {
            std::fs::remove_file(&paths.definition)?;
        }
        Ok(())
    }
}

fn install_transaction(
    manager: &Manager,
    paths: &Paths,
    current: &Path,
    definition: &str,
    ready: impl Fn() -> bool,
) -> Result<PathBuf> {
    manager.available()?;
    text_path(&paths.binary)?;
    text_path(&paths.state)?;
    text_path(&paths.definition)?;
    disjoint_paths(paths)?;
    let parent = paths.binary.parent().context("Missing binary directory")?;
    std::fs::create_dir_all(parent)?;
    safe_directory(parent)?;
    safe_directory(&paths.state)?;
    let _install_lock = lock_file(&parent.join(".agent-bridge-install.lock"))?;
    let old_definition = owned_regular(&paths.definition)?;
    if old_definition {
        safe_directory(
            paths
                .definition
                .parent()
                .context("Missing service directory")?,
        )?;
    }
    let was_active = manager.active()?;
    let was_enabled = old_definition && manager.enabled()?;
    ensure!(
        !was_active || old_definition,
        "An active service uses a definition outside the managed path; stop/reconfigure it explicitly before installing"
    );
    if old_definition {
        manager.validate_definition(paths)?;
    }
    if old_definition || was_active {
        manager.stop()?;
    }
    let state_guard = match lock_file(&paths.state.join("service.lock")) {
        Ok(guard) => guard,
        Err(error) => {
            if was_active {
                let _ = manager.start(&paths.definition);
            }
            return Err(error);
        }
    };
    let backup = match Backup::create(paths, was_active, was_enabled) {
        Ok(backup) => backup,
        Err(error) => {
            drop(state_guard);
            if was_active {
                let _ = manager.start(&paths.definition);
            }
            return Err(
                error.context("Could not back up stable state; executable was not replaced")
            );
        }
    };
    let mut guard = Some(state_guard);
    let attempt = (|| -> Result<()> {
        atomic_copy(current, &paths.binary, 0o755)?;
        if !old_definition {
            std::fs::create_dir_all(
                paths
                    .definition
                    .parent()
                    .context("Missing service directory")?,
            )?;
            safe_directory(
                paths
                    .definition
                    .parent()
                    .context("Missing service directory")?,
            )?;
            atomic_write(&paths.definition, definition.as_bytes(), 0o600)?;
        }
        manager.reload()?;
        manager.validate_definition(paths)?;
        manager.set_enabled(true)?;
        drop(guard.take());
        manager.start(&paths.definition)?;
        let until = Instant::now() + Duration::from_secs(10);
        while !ready() {
            ensure!(
                Instant::now() < until,
                "Installed service did not become ready; inspect its private logs"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    })();
    if let Err(error) = attempt {
        // Never restart an old executable against a migrated database.
        if paths.definition.exists() || manager.active()? {
            manager.stop().context("Upgrade failed and new service could not stop; restore manually from the private backup")?;
        }
        if !backup.old_definition && paths.definition.exists() {
            manager.set_enabled(false)?;
        }
        if guard.is_none() {
            guard = Some(
                lock_file(&paths.state.join("service.lock"))
                    .context("Cannot acquire state for rollback; private backup retained")?,
            );
        }
        backup.restore(paths).context("Could not restore upgrade backup; do not start the old executable until state is restored")?;
        manager.reload()?;
        if backup.old_definition {
            manager.set_enabled(backup.was_enabled)?;
        }
        drop(guard.take());
        if backup.was_active {
            manager
                .start(&paths.definition)
                .context("Old state/binary restored, but previous service did not restart")?;
        }
        anyhow::bail!(
            "Upgrade failed and previous binary/state/service were restored. Backup: {}. Cause: {error:#}",
            backup.directory.display()
        );
    }
    Ok(backup.directory)
}

pub fn install(state: &Path, _codex: Option<PathBuf>) -> Result<()> {
    let manager = Manager::native()?;
    // Check session availability before creating state or replacing any files.
    manager.available()?;
    let user_home = home()?;
    text_path(&user_home)?;
    let binary = installed_binary()?;
    let definition = match manager.kind {
        Kind::Linux => user_home.join(".config/systemd/user/agent-bridge.service"),
        Kind::Mac => user_home.join(format!("Library/LaunchAgents/{LABEL}.plist")),
    };
    let mut paths = Paths {
        binary: binary.clone(),
        state: state.to_path_buf(),
        definition: definition.clone(),
        backup_root: user_home.join(".local/state/agent-bridge-backups"),
    };
    disjoint_paths(&paths)?;
    crate::broker::private_dir(state)?;
    let state = state.canonicalize()?;
    paths.state = state.clone();
    let content = match manager.kind {
        Kind::Linux => systemd_unit(
            &binary,
            &state,
            &user_home,
            std::env::var_os("CODEX_HOME").as_deref().map(Path::new),
        )?,
        Kind::Mac => {
            let mut value = plist(&binary, &state, Path::new("/unused"));
            if let Some(codex_home) = std::env::var_os("CODEX_HOME") {
                let codex_home = PathBuf::from(codex_home);
                let home = text_path(&codex_home)?;
                value = value.replace(
                    "<key>PATH</key>",
                    &format!(
                        "<key>CODEX_HOME</key><string>{}</string><key>PATH</key>",
                        xml(home)
                    ),
                );
            }
            value
        }
    };
    let backup = install_transaction(
        &manager,
        &paths,
        &std::env::current_exe()?,
        &content,
        || service_ready(&state),
    )?;
    println!(
        "Installed user service\nBinary: {}\nState: {}\nService: {}\nPrivate backup: {}",
        binary.display(),
        state.display(),
        definition.display(),
        backup.display()
    );
    Ok(())
}

fn safe_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let actual = path.canonicalize()?;
    let leaf = std::fs::metadata(&actual)?;
    ensure!(
        leaf.is_dir() && leaf.uid() == unsafe { libc::geteuid() } && leaf.mode() & 0o022 == 0,
        "Installation directory must be owned by this user and not writable by others"
    );
    for ancestor in actual.ancestors().skip(1) {
        let meta = std::fs::metadata(ancestor)?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } || meta.uid() == 0,
            "Installation directory has a foreign-owned ancestor"
        );
        ensure!(
            meta.mode() & 0o022 == 0 || (meta.mode() & 0o1000 != 0 && meta.uid() == 0),
            "Installation directory has an unsafe writable ancestor"
        );
    }
    Ok(())
}
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        ensure!(
            result == 0 && length as usize == std::mem::size_of::<libc::ucred>(),
            "Cannot authenticate service socket peer"
        );
        Ok(credentials.uid)
    }
    #[cfg(target_os = "macos")]
    {
        let mut uid = 0;
        let mut gid = 0;
        ensure!(
            unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0,
            "Cannot authenticate service socket peer"
        );
        Ok(uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
        anyhow::bail!("Service peer authentication is unsupported on this platform")
    }
}

fn service_ready(state: &Path) -> bool {
    use std::io::{BufRead, BufReader, Read, Write};
    let probe = || -> Result<bool> {
        let mut stream = std::os::unix::net::UnixStream::connect(state.join("bridge.sock"))?;
        ensure!(
            peer_uid(&stream)? == unsafe { libc::geteuid() },
            "Service socket belongs to another user"
        );
        stream.set_read_timeout(Some(Duration::from_millis(250)))?;
        stream.set_write_timeout(Some(Duration::from_millis(250)))?;
        stream.write_all(b"{\"op\":\"status\"}\n")?;
        let mut line = String::new();
        BufReader::new(stream)
            .take(crate::protocol::MAX_FRAME as u64)
            .read_line(&mut line)?;
        let response: serde_json::Value = serde_json::from_str(&line)?;
        Ok(response["ok"] == true
            && response["result"]["state_dir"] == state.to_string_lossy().as_ref())
    };
    probe().unwrap_or(false)
}

pub fn uninstall() -> Result<()> {
    let manager = Manager::native()?;
    manager.available()?;
    let definition = match manager.kind {
        Kind::Linux => home()?.join(".config/systemd/user/agent-bridge.service"),
        Kind::Mac => home()?.join(format!("Library/LaunchAgents/{LABEL}.plist")),
    };
    let exists = owned_regular(&definition)?;
    if exists || manager.active()? {
        manager.stop()?;
    }
    if exists {
        manager.set_enabled(false)?;
        std::fs::remove_file(definition)?;
        manager.reload()?;
    }
    println!(
        "User service removed. Database, binary and private backups retained. Run hooks uninstall separately to remove native hooks."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    struct Fixture {
        _root: tempfile::TempDir,
        paths: Paths,
        manager: Manager,
        source: PathBuf,
        control: PathBuf,
    }
    impl Fixture {
        fn new(active: bool, enabled: bool, definition: bool) -> Self {
            let root = tempfile::Builder::new()
                .prefix("ab-service-unit-")
                .tempdir_in("/tmp")
                .unwrap();
            let base = root.path().canonicalize().unwrap();
            let binary = base.join("bin/agent-bridge");
            let state = base.join("state");
            let service = base.join("config/agent-bridge.service");
            for directory in [
                binary.parent().unwrap(),
                state.as_path(),
                service.parent().unwrap(),
            ] {
                crate::broker::private_dir(directory).unwrap();
            }
            atomic_write(&binary, b"original-binary", 0o755).unwrap();
            if definition {
                atomic_write(
                    &service,
                    format!(
                        "[Service]\nExecStart={} --state-dir {} serve\nEnvironment=CODEX_HOME=/custom/home\n",
                        binary.display(),state.display()
                    )
                    .as_bytes(),
                    0o600,
                )
                .unwrap();
            }
            let db = rusqlite::Connection::open(state.join("messages.sqlite3")).unwrap();
            db.execute_batch("PRAGMA user_version=6;CREATE TABLE messages(id TEXT PRIMARY KEY,body TEXT);INSERT INTO messages VALUES('original','history');").unwrap();
            drop(db);
            atomic_write(&state.join("identity.key"), b"private-key-fixture", 0o600).unwrap();
            let control = base.join("manager.json");
            atomic_write(&control,serde_json::to_vec(&serde_json::json!({"active":active,"enabled":enabled,"unavailable":false,"fail_once":false,"calls":[],"state":state,"definition":service})).unwrap().as_slice(),0o600).unwrap();
            let program = base.join("manager");
            let script = format!(
                r#"#!/usr/bin/env python3
import json,sys,sqlite3
p={control:?}
v=json.load(open(p));a=sys.argv[1:];v['calls'].append(a)
code=0
if a==['--user','show-environment']:
 code=int(v['unavailable'])
elif a==['--user','is-active','--quiet','agent-bridge.service']:
 code=int(not v['active'])
elif a==['--user','is-enabled','--quiet','agent-bridge.service']:
 code=int(not v['enabled'])
elif a==['--user','cat','agent-bridge.service']:
 print(v.get('override') or open(v['definition']).read())
elif a==['--user','stop','agent-bridge.service']:
 v['active']=False
elif a==['--user','start','agent-bridge.service']:
 if v['fail_once']:
  c=sqlite3.connect(v['state']+'/messages.sqlite3');c.execute('pragma user_version=10');c.execute("insert into messages values('new','migrated')");c.commit();c.close()
  open(v['state']+'/new-file','w').write('new-state')
  v['fail_once']=False;code=1
 else:v['active']=True
elif a==['--user','enable','agent-bridge.service']:v['enabled']=True
elif a==['--user','disable','agent-bridge.service']:v['enabled']=False
elif a!=['--user','daemon-reload']:raise AssertionError(a)
json.dump(v,open(p,'w'));sys.exit(code)
"#,
                control = control.to_str().unwrap()
            );
            atomic_write(&program, script.as_bytes(), 0o700).unwrap();
            let source = base.join("new-binary");
            atomic_write(&source, b"new-binary", 0o700).unwrap();
            Self {
                paths: Paths {
                    binary,
                    state,
                    definition: service,
                    backup_root: base.join("backups"),
                },
                manager: Manager {
                    kind: Kind::Linux,
                    program,
                },
                source,
                control,
                _root: root,
            }
        }
        fn config(&self) -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(&self.control).unwrap()).unwrap()
        }
        fn change(&self, key: &str, value: bool) {
            let mut v = self.config();
            v[key] = serde_json::json!(value);
            std::fs::write(&self.control, serde_json::to_vec(&v).unwrap()).unwrap();
        }
    }
    #[test]
    fn systemd_escapes_arguments_specifiers_and_environment_without_a_shell() {
        let unit = systemd_unit(
            Path::new("/home/user/$work%/a\"b\\/agent-bridge"),
            Path::new("/home/user/state with space"),
            Path::new("/home/user/$work%"),
            Some(Path::new("/home/user/codex")),
        )
        .unwrap();
        assert!(unit.contains("$$work%%/a\\\"b\\\\/agent-bridge"));
        assert!(unit.contains("\"/home/user/state with space\""));
        assert!(unit.contains("Environment=\"PATH=/home/user/$work%%/.local/bin:"));
        assert!(unit.contains("CODEX_HOME=/home/user/codex"));
        assert!(unit.contains("UMask=0077"));
        assert!(!unit.contains("--codex-bin"));
        assert!(
            systemd_unit(
                Path::new("/bin/a\nExecStart=bad"),
                Path::new("/state"),
                Path::new("/home/user"),
                None
            )
            .is_err()
        );
        let xml = plist(
            Path::new("/bin/a&b"),
            Path::new("/private/<state>"),
            Path::new("/missing/codex"),
        );
        assert!(xml.contains("/bin/a&amp;b"));
        assert!(!xml.contains("--codex-bin"));
    }
    #[test]
    fn private_snapshot_preserves_database_wal_keys_and_skips_sockets() {
        let f = Fixture::new(false, false, true);
        atomic_write(
            &f.paths.state.join("messages.sqlite3-wal"),
            b"wal-fixture",
            0o600,
        )
        .unwrap();
        atomic_write(
            &f.paths.state.join("messages.sqlite3-shm"),
            b"shm-fixture",
            0o600,
        )
        .unwrap();
        let _socket =
            std::os::unix::net::UnixListener::bind(f.paths.state.join("bridge.sock")).unwrap();
        let backup = Backup::create(&f.paths, false, false).unwrap();
        for file in [
            "messages.sqlite3",
            "messages.sqlite3-wal",
            "messages.sqlite3-shm",
            "identity.key",
        ] {
            assert_eq!(
                std::fs::read(f.paths.state.join(file)).unwrap(),
                std::fs::read(backup.directory.join("state").join(file)).unwrap()
            );
        }
        assert!(!backup.directory.join("state/bridge.sock").exists());
        assert_eq!(
            std::fs::metadata(&backup.directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        symlink(
            f.paths.state.join("identity.key"),
            f.paths.state.join("unsafe-link"),
        )
        .unwrap();
        assert!(Backup::create(&f.paths, false, false).is_err());
    }
    #[test]
    fn successful_upgrade_preserves_definition_identity_history_and_stops_before_copy() {
        let f = Fixture::new(true, true, true);
        let definition = std::fs::read(&f.paths.definition).unwrap();
        let backup = install_transaction(
            &f.manager,
            &f.paths,
            &f.source,
            "must-not-overwrite-custom-unit",
            || true,
        )
        .unwrap();
        assert_eq!(std::fs::read(&f.paths.binary).unwrap(), b"new-binary");
        assert_eq!(std::fs::read(&f.paths.definition).unwrap(), definition);
        assert_eq!(
            std::fs::read(backup.join("binary")).unwrap(),
            b"original-binary"
        );
        assert_eq!(
            std::fs::read(f.paths.state.join("identity.key")).unwrap(),
            b"private-key-fixture"
        );
        let calls = f.config()["calls"].as_array().unwrap().clone();
        let stop = calls.iter().position(|v| v[1] == "stop").unwrap();
        let start = calls.iter().position(|v| v[1] == "start").unwrap();
        assert!(stop < start);
        assert_eq!(f.config()["active"], true);
    }
    #[test]
    fn failed_migration_restores_old_binary_database_definition_and_service_state() {
        for active in [true, false] {
            let f = Fixture::new(active, false, true);
            let definition = std::fs::read(&f.paths.definition).unwrap();
            f.change("fail_once", true);
            let error = install_transaction(&f.manager, &f.paths, &f.source, "unused", || true)
                .unwrap_err();
            assert!(error.to_string().contains("restored"), "{error:#}");
            assert_eq!(std::fs::read(&f.paths.binary).unwrap(), b"original-binary");
            assert_eq!(std::fs::read(&f.paths.definition).unwrap(), definition);
            let db = rusqlite::Connection::open(f.paths.state.join("messages.sqlite3")).unwrap();
            assert_eq!(
                db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                    .unwrap(),
                6
            );
            assert_eq!(
                db.query_row::<i64, _, _>("select count(*) from messages", [], |r| r.get(0))
                    .unwrap(),
                1
            );
            assert!(!f.paths.state.join("new-file").exists());
            assert_eq!(f.config()["active"], active);
            assert_eq!(f.config()["enabled"], false);
        }
    }
    #[test]
    fn fresh_failure_removes_created_definition_and_enablement() {
        let f = Fixture::new(false, false, false);
        std::fs::remove_file(&f.paths.binary).unwrap();
        f.change("fail_once", true);
        assert!(
            install_transaction(
                &f.manager,
                &f.paths,
                &f.source,
                &systemd_unit(&f.paths.binary, &f.paths.state, f._root.path(), None).unwrap(),
                || true
            )
            .is_err()
        );
        assert!(!f.paths.binary.exists());
        assert!(!f.paths.definition.exists());
        assert_eq!(f.config()["active"], false);
        assert_eq!(f.config()["enabled"], false);
    }
    #[test]
    fn effective_definition_state_or_executable_mismatch_fails_before_stop() {
        for mismatch in ["state", "binary"] {
            let f = Fixture::new(true, true, true);
            let other = f._root.path().join("state-other");
            crate::broker::private_dir(&other).unwrap();
            let mut config = f.config();
            let binary = if mismatch == "binary" {
                f.paths.binary.with_file_name("agent-bridge-other")
            } else {
                f.paths.binary.clone()
            };
            let state = if mismatch == "state" {
                other
            } else {
                f.paths.state.clone()
            };
            config["override"] = serde_json::json!(format!(
                "[Service]\nExecStart=\nExecStart={} --state-dir {} serve\n",
                binary.display(),
                state.display()
            ));
            std::fs::write(&f.control, serde_json::to_vec(&config).unwrap()).unwrap();
            assert!(
                install_transaction(&f.manager, &f.paths, &f.source, "unused", || true).is_err()
            );
            assert_eq!(std::fs::read(&f.paths.binary).unwrap(), b"original-binary");
            assert!(!f.paths.backup_root.exists());
            assert!(
                !f.config()["calls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v[1] == "stop" || v[1] == "start")
            );
        }
    }
    #[test]
    fn effective_unit_parser_honors_reset_and_rejects_ambiguous_expansion() {
        assert_eq!(systemd_arguments("[Service]\nExecStart=/old serve\n[Service]\nExecStart=\nExecStart=\"/new path/agent-bridge\" --state-dir /state serve\n").unwrap()[0],"/new path/agent-bridge");
        for command in [
            "[Service]\nExecStart=%h/bin/agent-bridge serve",
            "[Service]\nExecStart=/bin/a $STATE serve",
            "[Service]\nExecStart=/one serve\nExecStart=/two serve",
            "[Service]\nEnvironment=HOME=/other\nExecStart=/one serve",
            "[Service]\nEnvironmentFile=/environment\nExecStart=/one serve",
            "[Service]\nRootDirectory=/other\nExecStart=/one --state-dir /state serve",
        ] {
            assert!(systemd_arguments(command).is_err());
        }
    }
    #[test]
    fn overlapping_or_aliased_state_and_backup_paths_fail_without_mutation() {
        for mode in [
            "backup-inside-state",
            "state-inside-backup",
            "backup-alias",
            "binary-parent",
            "config-parent",
        ] {
            let mut f = Fixture::new(true, true, true);
            match mode {
                "backup-inside-state" => f.paths.backup_root = f.paths.state.join("backups"),
                "state-inside-backup" => {
                    f.paths.backup_root = f._root.path().canonicalize().unwrap()
                }
                "backup-alias" => {
                    let alias = f._root.path().join("alias");
                    symlink(&f.paths.state, &alias).unwrap();
                    f.paths.backup_root = alias.join("backups");
                }
                "binary-parent" => f.paths.state = f.paths.binary.parent().unwrap().to_path_buf(),
                "config-parent" => {
                    f.paths.state = f.paths.definition.parent().unwrap().to_path_buf()
                }
                _ => unreachable!(),
            }
            let before = std::fs::read_dir(&f.paths.state).unwrap().count();
            assert!(
                install_transaction(&f.manager, &f.paths, &f.source, "unused", || true).is_err(),
                "{mode}"
            );
            assert!(Backup::create(&f.paths, true, true).is_err(), "{mode}");
            assert_eq!(std::fs::read_dir(&f.paths.state).unwrap().count(), before);
            assert_eq!(std::fs::read(&f.paths.binary).unwrap(), b"original-binary");
            assert!(
                !f.config()["calls"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v[1] == "stop" || v[1] == "start")
            );
        }
    }
    #[test]
    fn absent_user_bus_and_unmanaged_state_never_replace_the_binary() {
        let f = Fixture::new(false, false, false);
        f.change("unavailable", true);
        assert!(install_transaction(&f.manager, &f.paths, &f.source, "unused", || true).is_err());
        assert_eq!(std::fs::read(&f.paths.binary).unwrap(), b"original-binary");
        assert!(!f.paths.backup_root.exists());
        f.change("unavailable", false);
        let _guard = lock_file(&f.paths.state.join("service.lock")).unwrap();
        assert!(install_transaction(&f.manager, &f.paths, &f.source, "unused", || true).is_err());
        assert_eq!(std::fs::read(&f.paths.binary).unwrap(), b"original-binary");
        assert!(!f.paths.backup_root.exists());
    }
}
