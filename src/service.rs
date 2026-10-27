use anyhow::{Context, Result, ensure};
use std::{
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
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

pub fn plist(binary: &Path, state: &Path, codex: &Path) -> String {
    let args = [
        binary.to_string_lossy().into_owned(),
        "--state-dir".into(),
        state.to_string_lossy().into_owned(),
        "serve".into(),
        "--codex-bin".into(),
        codex.to_string_lossy().into_owned(),
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
fn plist_path() -> Result<PathBuf> {
    Ok(home()?.join(format!("Library/LaunchAgents/{LABEL}.plist")))
}

pub fn install(state: &Path, codex: Option<PathBuf>) -> Result<()> {
    ensure!(
        cfg!(target_os = "macos"),
        "launchd installation requires macOS; use serve on other Unix systems"
    );
    crate::broker::private_dir(state)?;
    let state = state.canonicalize()?;
    let codex = codex
        .or_else(|| find_binary("codex"))
        .context("Cannot locate codex; pass --codex-bin /absolute/path")?;
    ensure!(
        codex.is_absolute() && codex.is_file(),
        "codex executable must be an absolute file path"
    );
    let dest = installed_binary()?;
    std::fs::create_dir_all(dest.parent().unwrap())?;
    let current = std::env::current_exe()?;
    if current != dest {
        atomic_write(&dest, &std::fs::read(&current)?, 0o755)?;
    }
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    let path = plist_path()?;
    std::fs::create_dir_all(path.parent().unwrap())?;
    atomic_write(&path, plist(&dest, &state, &codex).as_bytes(), 0o600)?;
    let label = format!("{}/{LABEL}", domain());
    if Command::new("launchctl")
        .args(["print", &label])
        .output()?
        .status
        .success()
    {
        let out = Command::new("launchctl")
            .args(["bootout", &label])
            .output()?;
        ensure!(
            out.status.success(),
            "Could not stop old service: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while Command::new("launchctl")
            .args(["print", &label])
            .output()?
            .status
            .success()
        {
            ensure!(
                Instant::now() < deadline,
                "launchd did not finish unloading {LABEL}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    // launchd can still return EIO briefly after a successful bootout.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let out = Command::new("launchctl")
            .arg("bootstrap")
            .arg(domain())
            .arg(&path)
            .output()?;
        if out.status.success() {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while !service_ready(&state) {
        ensure!(
            Instant::now() < deadline,
            "LaunchAgent loaded but service did not become ready; inspect {}",
            state.join("service.stderr.log").display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    println!(
        "Installed {LABEL}\nBinary: {}\nState: {}\nLaunchAgent: {}",
        dest.display(),
        state.display(),
        path.display()
    );
    Ok(())
}

fn service_ready(state: &Path) -> bool {
    use std::io::{BufRead, BufReader, Write};
    let probe = || -> Result<bool> {
        let mut stream = std::os::unix::net::UnixStream::connect(state.join("bridge.sock"))?;
        stream.set_read_timeout(Some(Duration::from_millis(250)))?;
        stream.set_write_timeout(Some(Duration::from_millis(250)))?;
        stream.write_all(b"{\"op\":\"status\"}\n")?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        let response: serde_json::Value = serde_json::from_str(&line)?;
        Ok(response["ok"] == true
            && response["result"]["state_dir"] == state.to_string_lossy().as_ref())
    };
    probe().unwrap_or(false)
}

pub fn uninstall() -> Result<()> {
    let label = format!("{}/{LABEL}", domain());
    if Command::new("launchctl")
        .args(["print", &label])
        .output()?
        .status
        .success()
    {
        let out = Command::new("launchctl")
            .args(["bootout", &label])
            .output()?;
        ensure!(
            out.status.success(),
            "Could not stop service: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let path = plist_path()?;
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    println!(
        "Service removed. Database and binary retained. Run hooks uninstall separately to remove native hooks."
    );
    Ok(())
}
