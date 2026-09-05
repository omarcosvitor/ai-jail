//! ConPTY proxy for native Windows execution.

use crate::terminal_filter::{TerminalFilter, looks_like_terminal_reply};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::io::{IsTerminal, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::time::Duration;
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Console::{
    CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleMode,
    GetConsoleScreenBufferInfo, GetStdHandle, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE, SetConsoleMode,
};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

pub struct Pty;

pub fn open() -> Result<Pty, String> {
    Ok(Pty)
}

impl Pty {
    pub fn slave_path(&self) -> Option<std::path::PathBuf> {
        None
    }
}

pub fn parse_resize_redraw_key(spec: &str) -> Result<Option<Vec<u8>>, String> {
    let normalized = spec
        .trim()
        .to_ascii_lowercase()
        .replace(['_', '+', ' '], "-");
    if normalized.is_empty()
        || matches!(normalized.as_str(), "off" | "none" | "disabled")
    {
        return Ok(None);
    }
    let mut control = false;
    let mut key = None;
    for part in normalized.split('-').filter(|part| !part.is_empty()) {
        match part {
            "ctrl" | "control" => control = true,
            "shift" => {}
            value
                if value.len() == 1
                    && value.as_bytes()[0].is_ascii_alphabetic() =>
            {
                key = Some(value.as_bytes()[0].to_ascii_uppercase());
            }
            value => {
                return Err(format!("unsupported modifier or key {value:?}"));
            }
        }
    }
    if !control {
        return Err("only ctrl-based redraw keys are supported".into());
    }
    key.map(|key| Some(vec![key & 0x1f]))
        .ok_or_else(|| "missing final letter key".into())
}

fn console_handle(kind: u32) -> HANDLE {
    unsafe { GetStdHandle(kind) }
}

fn terminal_size() -> Option<PtySize> {
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    let ok = unsafe {
        GetConsoleScreenBufferInfo(console_handle(STD_OUTPUT_HANDLE), &mut info)
    };
    if ok == 0 {
        return None;
    }
    let cols =
        i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
    let rows =
        i32::from(info.srWindow.Bottom) - i32::from(info.srWindow.Top) + 1;
    (cols > 0 && rows > 0).then_some(PtySize {
        rows: rows as u16,
        cols: cols as u16,
        pixel_width: 0,
        pixel_height: 0,
    })
}

struct RawModeGuard {
    handle: HANDLE,
    saved: u32,
}

impl RawModeGuard {
    fn enter() -> Result<Self, String> {
        let handle = console_handle(STD_INPUT_HANDLE);
        let mut saved = 0;
        if unsafe { GetConsoleMode(handle, &mut saved) } == 0 {
            return Err(format!(
                "GetConsoleMode failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let raw = (saved
            & !(ENABLE_ECHO_INPUT
                | ENABLE_LINE_INPUT
                | ENABLE_PROCESSED_INPUT))
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        if unsafe { SetConsoleMode(handle, raw) } == 0 {
            return Err(format!(
                "SetConsoleMode failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { handle, saved })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            SetConsoleMode(self.handle, self.saved);
        }
    }
}

fn command_builder(command: &std::process::Command) -> CommandBuilder {
    let mut builder = CommandBuilder::new(command.get_program());
    builder.args(command.get_args());
    if let Some(directory) = command.get_current_dir() {
        builder.cwd(directory);
    }
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            builder.env(name, value);
        } else {
            builder.env_remove(name);
        }
    }
    builder
}

pub fn run_with_config(
    _pty: Pty,
    command: &mut std::process::Command,
    resize_redraw_key: Option<&[u8]>,
    config: &crate::config::Config,
    _status_bar: bool,
) -> Result<i32, String> {
    let size = terminal_size().unwrap_or_default();
    let pair = native_pty_system()
        .openpty(size)
        .map_err(|error| format!("Failed to open ConPTY: {error}"))?;
    let mut child = pair
        .slave
        .spawn_command(command_builder(command))
        .map_err(|error| format!("Failed to start Windows sandbox: {error}"))?;
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| format!("Failed to read ConPTY: {error}"))?;
    let terminal_passthrough = config.terminal_passthrough_enabled();
    let (output_sender, output_receiver) = std::sync::mpsc::channel();
    let output_thread = std::thread::spawn(move || {
        let result = (|| -> std::io::Result<()> {
            let mut filter = TerminalFilter::new();
            let mut stdout = std::io::stdout().lock();
            let mut buffer = [0u8; 8192];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                if terminal_passthrough {
                    stdout.write_all(&buffer[..read])?;
                } else {
                    stdout.write_all(&filter.feed(&buffer[..read]))?;
                }
                stdout.flush()?;
            }
            Ok(())
        })();
        let _ = output_sender.send(result);
    });

    let mut writer = pair
        .master
        .take_writer()
        .map_err(|error| format!("Failed to write ConPTY: {error}"))?;
    let _raw_mode = if std::io::stdin().is_terminal() {
        Some(RawModeGuard::enter()?)
    } else {
        None
    };
    let stdin_handle = std::io::stdin().as_raw_handle() as HANDLE;
    let mut stdin_open = true;
    let mut input = [0u8; 4096];
    let mut previous_size = size;

    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| {
            format!("Failed waiting for Windows sandbox: {error}")
        })? {
            break status;
        }

        if let Some(size) = terminal_size()
            && size != previous_size
        {
            pair.master
                .resize(size)
                .map_err(|error| format!("Failed to resize ConPTY: {error}"))?;
            previous_size = size;
            if let Some(key) = resize_redraw_key {
                writer.write_all(key).map_err(|error| {
                    format!("Failed to request redraw: {error}")
                })?;
                writer.flush().ok();
            }
        }

        if stdin_open
            && unsafe { WaitForSingleObject(stdin_handle, 20) } == WAIT_OBJECT_0
        {
            match std::io::stdin().read(&mut input) {
                Ok(0) => stdin_open = false,
                Ok(read)
                    if terminal_passthrough
                        || !looks_like_terminal_reply(&input[..read]) =>
                {
                    writer.write_all(&input[..read]).map_err(|error| {
                        format!("Failed forwarding input to ConPTY: {error}")
                    })?;
                    writer.flush().ok();
                }
                Ok(_) => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    return Err(format!(
                        "Failed reading terminal input: {error}"
                    ));
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    };

    drop(writer);
    drop(pair.master);
    let output_result = output_receiver
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| "Timed out draining ConPTY output".to_string())?;
    output_result
        .map_err(|error| format!("Failed writing terminal output: {error}"))?;
    output_thread
        .join()
        .map_err(|_| "ConPTY output thread panicked".to_string())?;
    crate::output::terminal_reset();
    Ok(status.exit_code() as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resize_redraw_key_parser_matches_unix_behavior() {
        assert_eq!(
            parse_resize_redraw_key("ctrl-shift-l").unwrap(),
            Some(vec![12])
        );
        assert_eq!(parse_resize_redraw_key("disabled").unwrap(), None);
        assert!(parse_resize_redraw_key("alt-l").is_err());
    }
}
