use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

fn is_link_like(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

pub(crate) fn ensure_regular_file_or_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_link_like(&metadata) => {
            Err(format!("{} is a symlink or reparse point", path.display()))
        }
        Ok(metadata) if !metadata.is_file() => Err(format!(
            "{} exists but is not a regular file",
            path.display()
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Cannot stat {}: {error}", path.display())),
    }
}

pub(crate) fn ensure_no_symlink_parents(path: &Path) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if is_link_like(&metadata) => {
                return Err(format!(
                    "{} has a symlink or reparse-point parent ({})",
                    path.display(),
                    current.display()
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(format!(
                    "Cannot stat {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

fn current_user_sid() -> Result<String, String> {
    let output = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("Failed to run whoami.exe: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "whoami.exe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let line = String::from_utf8_lossy(&output.stdout);
    let sid = line
        .trim()
        .rsplit(',')
        .next()
        .map(|value| value.trim().trim_matches('"'))
        .filter(|value| value.starts_with("S-1-"))
        .ok_or_else(|| {
            "Could not determine the current Windows user SID".to_string()
        })?;
    Ok(sid.to_string())
}

fn secure_file(path: &Path) -> Result<(), String> {
    let principal = format!("*{}:(F)", current_user_sid()?);
    let output = Command::new("icacls.exe")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(principal)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("Failed to run icacls.exe: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Failed to secure {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

struct TempGuard {
    path: PathBuf,
    armed: bool,
}

impl TempGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn write_atomic(
    path: &Path,
    contents: &str,
    create_parent_dirs: bool,
    fallback_stem: &str,
) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if create_parent_dirs {
        fs::create_dir_all(parent).map_err(|error| {
            format!("Cannot create directory {}: {error}", parent.display())
        })?;
    }

    let stem = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(fallback_stem);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temp =
        parent.join(format!(".{stem}.tmp.{}.{}", std::process::id(), nonce));
    let mut guard = TempGuard::new(temp.clone());
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| {
            format!("Failed to create {}: {error}", temp.display())
        })?;
    secure_file(&temp)?;
    file.write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| {
            format!("Failed to write {}: {error}", temp.display())
        })?;
    drop(file);

    fs::rename(&temp, path).map_err(|error| {
        format!("Failed to replace {} atomically: {error}", path.display())
    })?;
    guard.disarm();
    secure_file(path)
}

pub(crate) fn backup_file(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    ensure_regular_file_or_absent(path)?;
    let mut backup = path.as_os_str().to_owned();
    backup.push(".bak");
    let backup = PathBuf::from(backup);
    ensure_regular_file_or_absent(&backup)?;
    fs::copy(path, &backup).map_err(|error| {
        format!("Failed to backup {}: {error}", path.display())
    })?;
    secure_file(&backup)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_a_regular_file() {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-fsutil-windows-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config");
        write_atomic(&path, "first", false, "config").unwrap();
        write_atomic(&path, "second", false, "config").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        let _ = fs::remove_dir_all(dir);
    }
}
