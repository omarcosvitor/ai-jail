//! Persistent terminal status bar overlay for the ConPTY proxy.
//!
//! Layout: ` C:\path | command            ai-jail 1.20.2 `
//!
//! The ConPTY proxy forwards child bytes straight to the terminal instead of
//! rendering a vt100 virtual screen, so the overlay keeps its row with a
//! DECSTBM scroll region and the ConPTY is sized one row shorter. The child
//! cursor is read back from the console instead of the terminal's
//! save/restore cursor slot, which many TUIs also use. Nothing here runs from
//! a signal handler, so redraws are plain buffered writes.

use crate::config::Config;
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use windows_sys::Win32::System::Console::{
    CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo, GetStdHandle,
    STD_OUTPUT_HANDLE,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Pastel (bg, fg) pairs in xterm-256 indices, mirroring statusbar.rs.
const PASTEL_PALETTE: &[(u8, u8)] = &[
    (224, 52),  // mistyrose / dark red
    (223, 94),  // wheat / dark orange
    (230, 94),  // cornsilk / dark orange
    (194, 22),  // honeydew / dark green
    (195, 23),  // lightcyan / dark teal
    (189, 54),  // lavender / dark purple
    (218, 53),  // pink / dark magenta
    (255, 235), // off-white / near-black
];

// U+2026 HORIZONTAL ELLIPSIS: 1 visible column
const ELLIPSIS: char = '\u{2026}';
// U+2191 UPWARDS ARROW: 1 visible column
const UP_ARROW: char = '\u{2191}';
// U+1F511 KEY and U+1F5BC FRAME WITH PICTURE: typically 2 columns each
const KEY_BADGE: (&str, usize) = ("\u{1f511}", 2);
const PICTURE_BADGE: (&str, usize) = ("\u{1f5bc}", 2);

static ACTIVE: AtomicBool = AtomicBool::new(false);
static DIRTY: AtomicBool = AtomicBool::new(false);
static UPDATE_AVAILABLE: AtomicBool = AtomicBool::new(false);
static ARMED_ROWS: AtomicU16 = AtomicU16::new(0);
static STATE: OnceLock<State> = OnceLock::new();

struct State {
    directory: String,
    command: String,
    style: String,
    ssh: bool,
    pictures: bool,
    ro_maps: usize,
    rw_maps: usize,
}

struct Screen {
    rows: u16,
    cols: u16,
    cursor_row: u16,
    cursor_col: u16,
}

fn screen() -> Option<Screen> {
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } == 0 {
        return None;
    }
    let cols =
        i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
    let rows =
        i32::from(info.srWindow.Bottom) - i32::from(info.srWindow.Top) + 1;
    if cols <= 0 || rows <= 0 {
        return None;
    }
    let cursor_row =
        i32::from(info.dwCursorPosition.Y) - i32::from(info.srWindow.Top) + 1;
    let cursor_col =
        i32::from(info.dwCursorPosition.X) - i32::from(info.srWindow.Left) + 1;
    Some(Screen {
        rows: rows as u16,
        cols: cols as u16,
        cursor_row: cursor_row.clamp(1, rows) as u16,
        cursor_col: cursor_col.clamp(1, cols) as u16,
    })
}

fn write_out(sequence: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(sequence.as_bytes());
    let _ = stdout.flush();
}

/// Pick the SGR sequence for the status bar background. The pastel entry is
/// chosen once per session so the color stays stable for the whole run but
/// rotates between sessions.
fn style_sgr(style: &str) -> String {
    match style {
        "dark" => "\x1b[37;40m".into(),
        "light" => "\x1b[90;107m".into(),
        _ => {
            let elapsed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(std::time::Duration::ZERO);
            let seed =
                elapsed.as_secs() as usize ^ elapsed.subsec_nanos() as usize;
            let (bg, fg) = PASTEL_PALETTE[seed % PASTEL_PALETTE.len()];
            format!("\x1b[38;5;{fg};48;5;{bg}m")
        }
    }
}

fn truncate_directory(directory: &str, budget: usize) -> String {
    if budget == 0 {
        return String::new();
    }
    if directory.chars().count() <= budget {
        return directory.to_string();
    }
    if let Some(index) = directory.rfind(['\\', '/']) {
        let separator = &directory[index..index + 1];
        let segment = &directory[index + 1..];
        if segment.chars().count() + 2 <= budget {
            return format!("{ELLIPSIS}{separator}{segment}");
        }
    }
    if budget == 1 {
        return ELLIPSIS.to_string();
    }
    let skipped = directory.chars().count() - (budget - 1);
    let tail: String = directory.chars().skip(skipped).collect();
    format!("{ELLIPSIS}{tail}")
}

fn truncate_command(command: &str, budget: usize) -> String {
    if command.chars().count() <= budget {
        return command.to_string();
    }
    if budget == 1 {
        return ELLIPSIS.to_string();
    }
    let head: String = command.chars().take(budget - 1).collect();
    format!("{head}{ELLIPSIS}")
}

fn badges(state: &State) -> (String, usize) {
    let mut badges = String::new();
    let mut width = 0;
    let mut push = |text: &str, columns: usize| {
        if !badges.is_empty() {
            badges.push('|');
            width += 1;
        }
        badges.push_str(text);
        width += columns;
    };
    if state.ssh {
        push(KEY_BADGE.0, KEY_BADGE.1);
    }
    if state.pictures {
        push(PICTURE_BADGE.0, PICTURE_BADGE.1);
    }
    if state.ro_maps > 0 {
        let badge = format!("ro:{}", state.ro_maps);
        push(&badge, badge.chars().count());
    }
    if state.rw_maps > 0 {
        let badge = format!("rw:{}", state.rw_maps);
        push(&badge, badge.chars().count());
    }
    if badges.is_empty() {
        (badges, 0)
    } else {
        // Wrap the badge group with spaces: " badges ".
        (badges, width + 2)
    }
}

fn render(state: &State, cols: u16) -> String {
    // Leave the final terminal column blank to avoid wrap-pending artifacts
    // when terminals redraw during resize.
    let usable = (cols as usize).saturating_sub(1);
    let (badges, badge_width) = badges(state);
    let has_update = UPDATE_AVAILABLE.load(Ordering::SeqCst);

    // "ai-jail " (8) + VERSION + optional " ↑" (2) + badges
    let right_width =
        8 + VERSION.len() + if has_update { 2 } else { 0 } + badge_width;
    let show_right = usable >= right_width + 2;
    let left_budget = if show_right {
        usable.saturating_sub(right_width + 2)
    } else {
        usable.saturating_sub(1)
    };

    let mut line = String::new();
    let mut visible = 0;
    if usable > 0 {
        line.push(' ');
        visible += 1;
    }

    let directory = truncate_directory(&state.directory, left_budget);
    let directory_width = directory.chars().count();
    line.push_str(&directory);
    visible += directory_width;

    let remaining = left_budget.saturating_sub(directory_width);
    if remaining >= 4 && !state.command.is_empty() {
        let command = truncate_command(&state.command, remaining - 3);
        line.push_str(" | ");
        line.push_str(&command);
        visible += 3 + command.chars().count();
    }

    let target = if show_right {
        usable - right_width
    } else {
        usable
    };
    while visible < target {
        line.push(' ');
        visible += 1;
    }

    if show_right {
        if !badges.is_empty() {
            line.push(' ');
            line.push_str(&badges);
            line.push(' ');
            visible += badge_width;
        }
        line.push_str("ai-jail ");
        line.push_str(VERSION);
        visible += 8 + VERSION.len();
        if has_update {
            line.push_str(" \x1b[32m");
            line.push(UP_ARROW);
            line.push_str(&state.style);
            visible += 2;
        }
    }

    while visible < usable {
        line.push(' ');
        visible += 1;
    }
    line
}

/// Paint the overlay on the last row, optionally re-arming the scroll region
/// that keeps that row out of the child's reach. DECSTBM homes the cursor, so
/// the region is emitted inside the same write that restores the cursor.
fn draw(screen: &Screen, arm_region: bool) {
    let Some(state) = STATE.get() else {
        return;
    };
    let mut sequence = String::new();
    if arm_region {
        sequence.push_str(&format!("\x1b[1;{}r", screen.rows - 1));
    }
    sequence.push_str(&format!("\x1b[{};1H\x1b[2K", screen.rows));
    sequence.push_str(&state.style);
    sequence.push_str(&render(state, screen.cols));
    sequence.push_str(&format!(
        "\x1b[0m\x1b[{};{}H",
        screen.cursor_row, screen.cursor_col
    ));
    write_out(&sequence);
}

/// Set up the status bar. Call before spawning the child.
/// `style` must be `"dark"`, `"light"`, or `"pastel"`.
pub fn setup(
    project_dir: &Path,
    command: &[String],
    style: &str,
    config: &Config,
) {
    let _ = STATE.set(State {
        directory: crate::output::escape_control_bytes(
            &project_dir.to_string_lossy(),
        ),
        command: command
            .iter()
            .map(|argument| crate::output::escape_control_bytes(argument))
            .collect::<Vec<_>>()
            .join(" "),
        style: style_sgr(style),
        ssh: config.ssh_enabled(),
        pictures: config.pictures_enabled(),
        ro_maps: config.ro_maps.len(),
        rw_maps: config.rw_maps.len(),
    });

    let Some(screen) = screen() else {
        return;
    };
    if screen.rows < 2 {
        return;
    }
    ACTIVE.store(true, Ordering::SeqCst);
    DIRTY.store(false, Ordering::SeqCst);
    draw(&screen, false);
}

/// Whether the status bar is currently active.
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::SeqCst)
}

/// Consume and clear a pending redraw request.
pub fn take_requests() -> bool {
    DIRTY.swap(false, Ordering::SeqCst)
}

/// Repaint the overlay over whatever the child just wrote. The scroll region
/// is armed here rather than in `setup` so it only ever outlives a path that
/// reaches `teardown`, and is re-armed whenever the height changes.
pub fn redraw() {
    if !ACTIVE.load(Ordering::SeqCst) {
        return;
    }
    let Some(screen) = screen() else {
        return;
    };
    if screen.rows < 2 {
        return;
    }
    let arm_region =
        ARMED_ROWS.swap(screen.rows, Ordering::SeqCst) != screen.rows;
    draw(&screen, arm_region);
}

/// Tear down the status bar. Call after the child exits.
pub fn teardown() {
    if !ACTIVE.swap(false, Ordering::SeqCst) {
        return;
    }
    DIRTY.store(false, Ordering::SeqCst);
    ARMED_ROWS.store(0, Ordering::SeqCst);
    let rows = screen().map_or(24, |screen| screen.rows);
    write_out(&format!("\x1b[r\x1b[{rows};1H\x1b[2K"));
}

fn set_update_available() {
    UPDATE_AVAILABLE.store(true, Ordering::SeqCst);
    DIRTY.store(true, Ordering::SeqCst);
}

/// Spawn a background thread to check GitHub for a newer release.
/// Fire-and-forget; any error is silently ignored.
pub fn check_update_background() {
    std::thread::spawn(|| {
        let output = match std::process::Command::new("curl")
            .args([
                "-sL",
                "-m",
                "5",
                "-H",
                "Accept: application/vnd.github.v3+json",
                "https://api.github.com/repos/akitaonrails/ai-jail/releases/latest",
            ])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
        {
            Ok(o) if o.status.success() => o.stdout,
            _ => return,
        };

        let json: serde_json::Value = match serde_json::from_slice(&output) {
            Ok(v) => v,
            _ => return,
        };

        let tag = match json.get("tag_name").and_then(|v| v.as_str()) {
            Some(t) => t.trim_start_matches('v'),
            None => return,
        };

        if is_newer(tag, VERSION) {
            set_update_available();
        }
    });
}

/// Simple semver comparison: is `remote` newer than `local`?
fn is_newer(remote: &str, local: &str) -> bool {
    let parse = |s: &str| -> (u32, u32, u32) {
        let mut parts = s.split('.');
        let ma = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        let mi = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        let pa = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        (ma, mi, pa)
    };
    parse(remote) > parse(local)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> State {
        State {
            directory: r"C:\work\project".into(),
            command: "claude".into(),
            style: "\x1b[37;40m".into(),
            ssh: false,
            pictures: false,
            ro_maps: 0,
            rw_maps: 0,
        }
    }

    #[test]
    fn the_line_fills_every_column_but_the_last() {
        assert_eq!(render(&fixture(), 80).chars().count(), 79);
        assert_eq!(render(&fixture(), 40).chars().count(), 39);
    }

    #[test]
    fn the_line_carries_the_project_the_command_and_the_version() {
        let line = render(&fixture(), 80);
        assert!(line.contains(r"C:\work\project"));
        assert!(line.contains("claude"));
        assert!(line.contains(&format!("ai-jail {VERSION}")));
    }

    #[test]
    fn narrow_terminals_drop_the_right_section() {
        let line = render(&fixture(), 16);
        assert!(!line.contains("ai-jail"));
        assert_eq!(line.chars().count(), 15);
    }

    #[test]
    fn capability_and_map_badges_reach_the_line() {
        let state = State {
            ssh: true,
            pictures: true,
            ro_maps: 2,
            rw_maps: 1,
            ..fixture()
        };
        let line = render(&state, 120);
        assert!(line.contains(KEY_BADGE.0));
        assert!(line.contains(PICTURE_BADGE.0));
        assert!(line.contains("ro:2|rw:1"));
        // Two badges render one char each but claim two columns.
        assert_eq!(line.chars().count(), 119 - 2);
    }

    #[test]
    fn directory_truncation_prefers_the_last_segment() {
        let long = r"C:\Users\dev\Documents\projects\deeply\nested\app";
        assert_eq!(truncate_directory(long, 8), format!("{ELLIPSIS}\\app"));
        assert_eq!(truncate_directory(long, 3), format!("{ELLIPSIS}pp"));
        assert_eq!(truncate_directory(long, 1), ELLIPSIS.to_string());
        assert_eq!(truncate_directory(long, 0), "");
    }

    #[test]
    fn command_truncation_keeps_the_head() {
        assert_eq!(
            truncate_command("claude --dangerously", 8),
            format!("claude {ELLIPSIS}")
        );
        assert_eq!(truncate_command("claude", 8), "claude");
    }

    #[test]
    fn each_style_maps_to_its_own_sgr_sequence() {
        assert_eq!(style_sgr("dark"), "\x1b[37;40m");
        assert_eq!(style_sgr("light"), "\x1b[90;107m");
        assert!(style_sgr("pastel").starts_with("\x1b[38;5;"));
    }

    #[test]
    fn is_newer_basic() {
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("0.4.6", "0.4.5"));
        assert!(!is_newer("0.4.5", "0.4.5"));
        assert!(!is_newer("0.3.0", "0.4.5"));
    }
}
