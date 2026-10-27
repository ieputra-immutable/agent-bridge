//! A read-only, local Markdown view. Board content defines its own schema.
use crate::{board::Snapshot, broker, protocol::Request};
use anyhow::{Context, Result, ensure};
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Paragraph, Wrap},
};
use std::{
    borrow::Cow,
    io::IsTerminal,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle};

const FALLBACK_REFRESH: Duration = Duration::from_secs(1);
// Tables with many sparse cells can expand far beyond their Markdown input.
// Leave such documents readable as plain Markdown instead of allocating a huge grid.
const MAX_TABLE_CELLS: usize = 20_000;

struct TerminalRestore;
impl Drop for TerminalRestore {
    fn drop(&mut self) {
        ratatui::restore();
    }
}
struct AbortWorker(JoinHandle<()>);
impl Drop for AbortWorker {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Keep Markdown newlines, normalize tabs, and remove terminal control sequences'
/// introducers. This changes display text only, never the stored document.
fn safe_markdown(input: &str) -> String {
    let mut safe = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' => safe.push('\n'),
            '\t' => safe.push_str("    "),
            ch if ch.is_control() => (),
            ch => safe.push(ch),
        }
    }
    safe
}

fn safe_line(input: &str) -> String {
    input
        .chars()
        .filter_map(|ch| match ch {
            '\n' | '\r' | '\t' => Some(' '),
            ch if ch.is_control() => None,
            ch => Some(ch),
        })
        .collect()
}

fn rendered_markdown(markdown: &str, width: u16) -> (Text<'static>, bool) {
    let safe = safe_markdown(markdown);
    let lines = safe.lines().count();
    let columns = safe
        .lines()
        .map(|line| line.bytes().filter(|byte| *byte == b'|').count())
        .max()
        .unwrap_or(0);
    let plain = columns.saturating_mul(lines) > MAX_TABLE_CELLS;
    let rendered = if plain {
        Text::from(safe.as_str())
    } else {
        let options = tui_markdown::Options::default().table_width(width);
        tui_markdown::from_str_with_options(&safe, &options)
    };
    // Entity decoding can introduce controls that were absent from the source,
    // e.g. &#x1b;. Sanitize every final span, not just the Markdown input.
    let owned = Text {
        alignment: rendered.alignment,
        style: rendered.style,
        lines: rendered
            .lines
            .into_iter()
            .map(|line| Line {
                alignment: line.alignment,
                style: line.style,
                spans: line
                    .spans
                    .into_iter()
                    .map(|span| Span {
                        style: span.style,
                        content: Cow::Owned(safe_line(&span.content)),
                    })
                    .collect(),
            })
            .collect(),
    };
    (owned, plain)
}

struct View {
    snapshot: Option<Snapshot>,
    error: Option<String>,
    rendered: Text<'static>,
    width: u16,
    scroll: (u16, u16),
    max_scroll: (u16, u16),
    wrap: bool,
    plain: bool,
}
impl Default for View {
    fn default() -> Self {
        Self {
            snapshot: None,
            error: None,
            rendered: Text::default(),
            width: 0,
            scroll: (0, 0),
            max_scroll: (0, 0),
            wrap: true,
            plain: false,
        }
    }
}
impl View {
    fn update(&mut self, result: Result<Snapshot>) {
        match result {
            Ok(snapshot) => {
                if self.snapshot.as_ref().map(|old| &old.revision) != Some(&snapshot.revision) {
                    self.width = 0;
                }
                self.snapshot = Some(snapshot);
                self.error = None;
            }
            Err(error) => self.error = Some(safe_line(&format!("{error:#}"))),
        }
    }
    fn paragraph(&self) -> Paragraph<'static> {
        let paragraph = Paragraph::new(self.rendered.clone());
        if self.wrap {
            paragraph.wrap(Wrap { trim: false })
        } else {
            paragraph
        }
    }
    fn draw(&mut self, frame: &mut Frame<'_>) {
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .areas(frame.area());
        let (name, revision) = self
            .snapshot
            .as_ref()
            .map(|snapshot| {
                (
                    safe_line(&snapshot.name),
                    snapshot.revision.chars().take(12).collect::<String>(),
                )
            })
            .unwrap_or_else(|| ("main".into(), "connecting".into()));
        frame.render_widget(
            Paragraph::new(format!(
                "Local shared board · {name} · {}",
                safe_line(&revision)
            ))
            .style(Style::default().fg(Color::Cyan)),
            header,
        );
        let path = self
            .snapshot
            .as_ref()
            .map(|snapshot| safe_line(&snapshot.path.to_string_lossy()))
            .unwrap_or_default();
        let block = Block::bordered().title(path);
        let inner = block.inner(body);
        if self.width != inner.width {
            let markdown = self
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.markdown.as_str())
                .unwrap_or("");
            (self.rendered, self.plain) = rendered_markdown(markdown, inner.width);
            self.width = inner.width;
        }
        let content_height = self.paragraph().line_count(inner.width);
        self.max_scroll = (
            content_height
                .saturating_sub(usize::from(inner.height))
                .min(usize::from(u16::MAX)) as u16,
            if self.wrap {
                0
            } else {
                self.rendered
                    .width()
                    .saturating_sub(usize::from(inner.width))
                    .min(usize::from(u16::MAX)) as u16
            },
        );
        self.scroll.0 = self.scroll.0.min(self.max_scroll.0);
        self.scroll.1 = self.scroll.1.min(self.max_scroll.1);
        frame.render_widget(block, body);
        frame.render_widget(self.paragraph().scroll(self.scroll), inner);
        let status = if let Some(error) = &self.error {
            format!("Offline/stale: {error} · retrying")
        } else if self.snapshot.is_none() {
            "Connecting to the local broker…".into()
        } else if self.plain {
            "Complex table shown as plain Markdown".into()
        } else if self
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.markdown.is_empty())
        {
            "Empty board · ask an agent to update it with the board MCP tools".into()
        } else {
            format!(
                "Live · wrap {} · line {}",
                if self.wrap { "on" } else { "off" },
                usize::from(self.scroll.0) + 1
            )
        };
        frame.render_widget(Paragraph::new(vec![
            Line::from(status),
            Line::from("q/Esc quit · j/k or arrows scroll · PgUp/PgDn · Home/End · h/l pan · w wrap · r refresh"),
        ]), footer);
    }
    fn key(&mut self, key: KeyEvent, page: u16) -> bool {
        if key.kind == KeyEventKind::Release {
            return false;
        }
        if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
            || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            return true;
        }
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => self.scroll.0 = self.scroll.0.saturating_add(1),
            KeyCode::Up | KeyCode::Char('k') => self.scroll.0 = self.scroll.0.saturating_sub(1),
            KeyCode::PageDown => self.scroll.0 = self.scroll.0.saturating_add(page.max(1)),
            KeyCode::PageUp => self.scroll.0 = self.scroll.0.saturating_sub(page.max(1)),
            KeyCode::Home => self.scroll = (0, 0),
            KeyCode::End => self.scroll.0 = self.max_scroll.0,
            KeyCode::Right | KeyCode::Char('l') => {
                self.wrap = false;
                self.scroll.1 = self.scroll.1.saturating_add(4);
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.wrap = false;
                self.scroll.1 = self.scroll.1.saturating_sub(4);
            }
            KeyCode::Char('w') => self.wrap = !self.wrap,
            _ => (),
        }
        false
    }
}

struct FileWatch {
    root: PathBuf,
    _watcher: RecommendedWatcher,
}
fn board_event(event: &notify::Event, board: &Path, parent: &Path) -> bool {
    !matches!(event.kind, notify::EventKind::Access(_))
        && event
            .paths
            .iter()
            .any(|path| path == board || path == parent)
}

fn file_watch(path: &Path, state_dir: &Path, refresh: mpsc::Sender<()>) -> Result<FileWatch> {
    let parent = path
        .parent()
        .context("Board path has no parent")?
        .to_path_buf();
    let root = if parent.is_dir() {
        parent.clone()
    } else {
        state_dir.to_path_buf()
    };
    let board = path.to_path_buf();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        if event.map_or(true, |event| board_event(&event, &board, &parent)) {
            let _ = refresh.try_send(());
        }
    })?;
    watcher.watch(&root, RecursiveMode::NonRecursive)?;
    Ok(FileWatch {
        root,
        _watcher: watcher,
    })
}

pub async fn run(state_dir: PathBuf) -> Result<()> {
    ensure!(
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        "The board viewer needs an interactive terminal; use board --raw to print Markdown"
    );
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let _restore = TerminalRestore;
    let mut terminal = ratatui::try_init().context("Cannot initialize the board terminal")?;
    let mut events = EventStream::new();
    let (refresh, mut requests) = mpsc::channel(1);
    let (updates, mut results) = mpsc::channel(1);
    let state = state_dir.clone();
    let worker = tokio::spawn(async move {
        while requests.recv().await.is_some() {
            let result = async {
                let value = broker::rpc(&state, &Request::BoardRead).await?;
                serde_json::from_value::<Snapshot>(value)
                    .context("Invalid board snapshot from broker")
            }
            .await;
            if updates.send(result).await.is_err() {
                break;
            }
        }
    });
    let _worker = AbortWorker(worker);
    let _ = refresh.try_send(());
    let mut fallback = tokio::time::interval(FALLBACK_REFRESH);
    fallback.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut view = View::default();
    let mut watch: Option<FileWatch> = None;
    let mut dirty = true;
    loop {
        if dirty {
            terminal.draw(|frame| view.draw(frame))?;
            dirty = false;
        }
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            event = events.next() => match event {
                Some(Ok(Event::Key(key))) => {
                    if view.key(key, terminal.size()?.height.saturating_sub(4)) { break; }
                    if key.code == KeyCode::Char('r') { let _ = refresh.try_send(()); }
                    dirty = true;
                }
                Some(Ok(Event::Resize(..))) => dirty = true,
                Some(Ok(_)) => (),
                Some(Err(error)) => return Err(error).context("Cannot read terminal input"),
                None => break,
            },
            _ = fallback.tick() => { let _ = refresh.try_send(()); },
            update = results.recv() => {
                let Some(update) = update else { anyhow::bail!("Board refresh worker stopped"); };
                if let Ok(snapshot) = &update {
                    let root = snapshot.path.parent().filter(|parent| parent.is_dir()).unwrap_or(&state_dir);
                    if watch.as_ref().is_none_or(|watch| watch.root != root) {
                        // Watching is an optimization; the bounded periodic refresh also
                        // handles unsupported filesystems and atomic replacement races.
                        watch = file_watch(&snapshot.path, &state_dir, refresh.clone()).ok();
                    }
                }
                view.update(update);
                dirty = true;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn snapshot(markdown: &str, revision: &str) -> Snapshot {
        Snapshot {
            name: "main".into(),
            markdown: markdown.into(),
            revision: revision.into(),
            path: PathBuf::from("/private/boards/main.md"),
            exists: true,
        }
    }
    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }
    #[test]
    fn generic_markdown_headings_tables_and_unicode_render() {
        let mut view = View::default();
        view.update(Ok(snapshot(
            "# Any subject\n\n| Planet | Note |\n|---|---|\n| 地球 | Ready ✅ |\n",
            "one",
        )));
        let mut terminal = Terminal::new(TestBackend::new(70, 15)).unwrap();
        terminal.draw(|frame| view.draw(frame)).unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("Any subject"));
        assert!(text.contains("Planet"));
        assert!(text.contains("Ready"));
        assert!(text.contains('地'));
        assert!(text.contains('│'));
    }
    #[test]
    fn raw_and_entity_encoded_terminal_controls_never_reach_spans() {
        let (text, _) = rendered_markdown(
            "# Safe\u{1b}]52;c;secret\u{7}\n&#x1b;]0;title&#7; &#x9b;2J",
            80,
        );
        for span in text.lines.iter().flat_map(|line| &line.spans) {
            assert!(
                !span.content.chars().any(char::is_control),
                "{:?}",
                span.content
            );
        }
        assert!(
            !safe_line("error\u{1b}]0;evil\u{7}\r\nnext")
                .chars()
                .any(char::is_control)
        );
    }
    #[test]
    fn updates_preserve_scroll_and_errors_preserve_last_good_content() {
        let mut view = View::default();
        let markdown = (0..100)
            .map(|line| format!("line {line}  \n"))
            .collect::<String>();
        view.update(Ok(snapshot(&markdown, "one")));
        let mut terminal = Terminal::new(TestBackend::new(70, 10)).unwrap();
        terminal.draw(|frame| view.draw(frame)).unwrap();
        view.scroll.0 = 20;
        view.update(Ok(snapshot(
            &markdown.replace("line 50", "updated 50"),
            "two",
        )));
        terminal.draw(|frame| view.draw(frame)).unwrap();
        assert_eq!(view.scroll.0, 20);
        view.update(Err(anyhow::anyhow!("offline")));
        terminal.draw(|frame| view.draw(frame)).unwrap();
        assert!(buffer_text(&terminal).contains("Offline/stale"));
        assert_eq!(view.snapshot.as_ref().unwrap().revision, "two");
    }
    #[test]
    fn pathological_sparse_tables_fall_back_to_plain_markdown() {
        let markdown = format!("{}\n{}", "|x".repeat(1000), "|\n".repeat(100));
        let (text, plain) = rendered_markdown(&markdown, 80);
        assert!(plain);
        assert!(text.lines.len() > 50);
    }
    #[test]
    fn file_reads_do_not_trigger_refresh_feedback() {
        use notify::event::{AccessKind, DataChange, ModifyKind};
        let board = Path::new("/private/boards/main.md");
        let parent = board.parent().unwrap();
        let read =
            notify::Event::new(notify::EventKind::Access(AccessKind::Read)).add_path(board.into());
        assert!(!board_event(&read, board, parent));
        let update =
            notify::Event::new(notify::EventKind::Modify(ModifyKind::Data(DataChange::Any)))
                .add_path(board.into());
        assert!(board_event(&update, board, parent));
        let unrelated = notify::Event::new(notify::EventKind::Modify(ModifyKind::Any))
            .add_path(PathBuf::from("/private/messages.sqlite3"));
        assert!(!board_event(&unrelated, board, parent));
    }

    #[test]
    fn tiny_and_resized_views_do_not_panic_and_keys_scroll() {
        let mut view = View::default();
        view.update(Ok(snapshot("# Heading\n\nText", "one")));
        let mut terminal = Terminal::new(TestBackend::new(1, 1)).unwrap();
        terminal.draw(|frame| view.draw(frame)).unwrap();
        view.key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE), 10);
        assert_eq!(view.scroll.0, 10);
        assert!(view.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL), 10));
        assert!(!view.key(
            KeyEvent::new_with_kind(
                KeyCode::Char('q'),
                KeyModifiers::NONE,
                KeyEventKind::Release
            ),
            10
        ));
    }
}
