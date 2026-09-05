//! Native Windows sandbox backed by Microsoft's ProcessContainer executor.

use super::{MapSpec, effective_mask_patterns, expand_mask_patterns};
use crate::config::Config;
use crate::output;
use serde_json::{Value, json};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const WXC_PACKAGE: &str = "@microsoft/mxc-sdk";

#[derive(Debug)]
pub struct SandboxGuard {
    wxc_exec: PathBuf,
}

fn architecture_dir() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    }
}

fn executable_file(path: &Path) -> bool {
    path.metadata().is_ok_and(|metadata| metadata.is_file())
}

fn find_wxc_exec() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("WXC_EXEC_BIN") {
        let path = PathBuf::from(path);
        if executable_file(&path) {
            return Ok(path);
        }
        return Err(format!(
            "WXC_EXEC_BIN does not point to a file: {}",
            path.display()
        ));
    }

    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        candidates.push(parent.join("wxc-exec.exe"));
    }
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(
            std::env::split_paths(&path).map(|dir| dir.join("wxc-exec.exe")),
        );
    }
    if let Some(appdata) = std::env::var_os("APPDATA") {
        candidates.push(
            PathBuf::from(appdata)
                .join("npm")
                .join("node_modules")
                .join(WXC_PACKAGE)
                .join("bin")
                .join(architecture_dir())
                .join("wxc-exec.exe"),
        );
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        candidates.push(
            PathBuf::from(program_files)
                .join("nodejs")
                .join("node_modules")
                .join(WXC_PACKAGE)
                .join("bin")
                .join(architecture_dir())
                .join("wxc-exec.exe"),
        );
    }

    candidates
        .into_iter()
        .find(|path| executable_file(path))
        .ok_or_else(|| {
            format!(
                "wxc-exec.exe not found. Install the native Windows backend with \
                 `npm install -g {WXC_PACKAGE}@0.8.0`, or set WXC_EXEC_BIN"
            )
        })
}

pub fn check() -> Result<(), String> {
    let executable = find_wxc_exec()?;
    let output = Command::new(&executable)
        .arg("--probe")
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("Failed to probe Windows sandbox: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Windows ProcessContainer is unavailable: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let probe: Value =
        serde_json::from_slice(&output.stdout).map_err(|error| {
            format!("Invalid wxc-exec --probe response: {error}")
        })?;
    let tier = probe.get("tier").and_then(Value::as_str).ok_or_else(|| {
        "wxc-exec --probe did not report an isolation tier".to_string()
    })?;
    if tier.is_empty() || tier == "unsupported" || tier == "unavailable" {
        return Err(format!(
            "Windows ProcessContainer is unavailable (reported tier: {tier})"
        ));
    }
    Ok(())
}

pub fn prepare() -> Result<SandboxGuard, String> {
    Ok(SandboxGuard {
        wxc_exec: find_wxc_exec()?,
    })
}

pub fn platform_notes(config: &Config) {
    if !config.overlay_maps.is_empty() {
        output::warn("Overlay maps are exposed read-only on Windows");
    }
    if config.docker_enabled() {
        output::warn(
            "Docker named-pipe passthrough is not available on Windows",
        );
    }
    if config.tailscale_enabled() {
        output::warn(
            "Tailscale socket passthrough is not available on Windows",
        );
    }
    if config.ssh_enabled() && std::env::var_os("SSH_AUTH_SOCK").is_some() {
        output::warn(
            "SSH keys are exposed read-only; SSH agent pipe passthrough is not available on Windows",
        );
    }
    if config.browser_profile().is_some() {
        output::warn("Browser profile rewriting is not available on Windows");
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

fn push_unique(paths: &mut Vec<PathBuf>, path: PathBuf) {
    if !paths.iter().any(|existing| same_path(existing, &path)) {
        paths.push(path);
    }
}

fn volume_root(path: &Path) -> Option<PathBuf> {
    let mut root = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                root.push(component.as_os_str());
            }
            _ => break,
        }
    }
    root.has_root().then_some(root)
}

fn add_volume_roots(readwrite: &[PathBuf], readonly: &mut Vec<PathBuf>) {
    let paths = readwrite
        .iter()
        .chain(readonly.iter())
        .filter_map(|path| volume_root(path))
        .collect::<Vec<_>>();
    for root in paths {
        push_unique(readonly, root);
    }
}

fn add_private_home_denials(
    home: &Path,
    readwrite: &[PathBuf],
    readonly: &[PathBuf],
    denied: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(home).map_err(|error| {
        format!(
            "Cannot enumerate the private home {}: {error}",
            home.display()
        )
    })?;
    for entry in entries {
        let path = entry
            .map_err(|error| {
                format!(
                    "Cannot enumerate the private home {}: {error}",
                    home.display()
                )
            })?
            .path();
        // Loaded registry hives are already locked by Windows. Asking MXC to
        // add a deny rule to them fails the entire launch with sharing
        // violation (ERROR_SHARING_VIOLATION).
        if path.file_name().is_some_and(|name| {
            name.to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("ntuser.dat")
        }) {
            continue;
        }
        if readwrite
            .iter()
            .chain(readonly)
            .any(|allowed| same_path(allowed, &path))
        {
            continue;
        }
        push_unique(denied, path);
    }
    Ok(())
}

fn executable_extensions() -> Vec<String> {
    std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
        .split(';')
        .filter(|extension| !extension.is_empty())
        .map(str::to_string)
        .collect()
}

fn executable_variants(path: &Path) -> Vec<PathBuf> {
    let mut paths = vec![path.to_path_buf()];
    if path.extension().is_none() {
        let base = path.as_os_str().to_string_lossy();
        paths.extend(
            executable_extensions()
                .into_iter()
                .map(|extension| PathBuf::from(format!("{base}{extension}"))),
        );
    }
    paths
}

fn resolve_executable(program: &str, project_dir: &Path) -> Option<PathBuf> {
    let program_path = Path::new(program);
    if program_path.is_absolute() || program_path.components().count() > 1 {
        let path = if program_path.is_absolute() {
            program_path.to_path_buf()
        } else {
            project_dir.join(program_path)
        };
        return executable_variants(&path)
            .into_iter()
            .find(|candidate| executable_file(candidate));
    }

    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .flat_map(|dir| executable_variants(&dir.join(program)))
            .find(|candidate| executable_file(candidate))
    })
}

fn map_sources(
    paths: &[PathBuf],
    access: &str,
) -> Result<Vec<PathBuf>, String> {
    let mut result = Vec::new();
    for encoded in paths {
        let Some(spec) = MapSpec::parse_validated(encoded, access) else {
            continue;
        };
        if spec.is_alternate() {
            return Err(format!(
                "alternate map destinations are not supported on Windows: {}; \
                 map the path at its host location",
                encoded.display()
            ));
        }
        if super::path_exists(&spec.source) {
            push_unique(&mut result, spec.source);
        } else {
            output::warn(&format!(
                "Path {} not found, skipping.",
                spec.source.display()
            ));
        }
    }
    Ok(result)
}

fn state_path_hidden(relative: &str, hidden: &[String]) -> bool {
    let top = relative
        .split(['/', '\\'])
        .next()
        .unwrap_or(relative)
        .trim_start_matches('.');
    hidden
        .iter()
        .any(|value| value.trim_start_matches('.').eq_ignore_ascii_case(top))
}

fn agent_state_paths(config: &Config, home: &Path) -> Vec<PathBuf> {
    if !config.agent_state_enabled() {
        return Vec::new();
    }
    let relative: &[&str] =
        match crate::command::effective_name(&config.command) {
            Some("claude") => &[".claude", ".claude.json"],
            Some("codex") => &[".codex"],
            Some("opencode") => &[".config/opencode", ".local/share/opencode"],
            Some("crush") => &[".crush"],
            Some(name) if name.starts_with("kimi") => &[".kimi-code"],
            Some("gemini") => &[".gemini"],
            Some("grok") => &[".grok"],
            Some("jcode") => &[".jcode", ".config/jcode"],
            Some("pi") => &[".pi", ".pi-lens"],
            Some("aider") => &[".aider"],
            Some("soulforge") => &[".soulforge"],
            Some("omp") => &[".omp"],
            _ => &[],
        };
    relative
        .iter()
        .filter(|path| !state_path_hidden(path, &config.hide_dotdirs))
        .map(|path| home.join(path.replace('/', "\\")))
        .filter(|path| super::path_exists(path))
        .collect()
}

fn child_environment(config: &Config) -> Vec<String> {
    let host: Vec<(String, String)> = std::env::vars().collect();
    let mut environment = if config.lockdown_enabled() {
        host.iter()
            .filter(|(name, _)| {
                [
                    "SystemRoot",
                    "WINDIR",
                    "COMSPEC",
                    "PATHEXT",
                    "USERPROFILE",
                    "HOMEDRIVE",
                    "HOMEPATH",
                    "TERM",
                    "COLORTERM",
                ]
                .iter()
                .any(|allowed| name.eq_ignore_ascii_case(allowed))
            })
            .cloned()
            .collect::<Vec<_>>()
    } else if config.inherit_env_enabled() {
        let mut environment = host.clone();
        crate::config::apply_env_pass(
            &mut environment,
            config.env_pass(),
            &host,
        );
        environment
    } else {
        crate::config::filtered_child_env(config.env_pass(), &host)
    };

    if config.lockdown_enabled()
        && let Some(system_root) = std::env::var_os("SystemRoot")
    {
        let root = PathBuf::from(system_root);
        let path = [
            root.join("System32"),
            root.clone(),
            root.join("System32").join("WindowsPowerShell").join("v1.0"),
        ];
        let value = std::env::join_paths(path)
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        environment.retain(|(name, _)| !name.eq_ignore_ascii_case("PATH"));
        environment.push(("PATH".into(), value));
    }
    if let Some(dir) = &config.claude_dir {
        environment.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("CLAUDE_CONFIG_DIR")
        });
        environment.push((
            "CLAUDE_CONFIG_DIR".into(),
            dir.to_string_lossy().into_owned(),
        ));
    }
    environment.push(("AI_JAIL".into(), "1".into()));
    environment
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect()
}

fn launch_argv(config: &Config, project_dir: &Path) -> Vec<String> {
    let mut argv = if config.command.is_empty() {
        vec!["powershell.exe".into(), "-NoLogo".into()]
    } else {
        config.command.clone()
    };
    if let Some(program) = argv.first_mut()
        && let Some(resolved) = resolve_executable(program, project_dir)
    {
        *program = resolved.to_string_lossy().into_owned();
    }
    argv
}

fn build_policy(
    config: &Config,
    project_dir: &Path,
) -> Result<(Value, Vec<String>), String> {
    let lockdown = config.lockdown_enabled();
    let home = super::home_dir();
    let mut readwrite = Vec::new();
    let mut readonly = Vec::new();
    let mut denied = effective_mask_patterns(config, project_dir);

    if lockdown {
        push_unique(&mut readonly, project_dir.to_path_buf());
    } else {
        push_unique(&mut readwrite, project_dir.to_path_buf());
    }

    if !lockdown {
        if !config.private_home_enabled() {
            push_unique(&mut readwrite, home.clone());
            let exemptions = super::dotdir_exemptions(config);
            for name in super::denied_dotdirs(&config.hide_dotdirs, &exemptions)
            {
                let path = home.join(format!(".{name}"));
                if super::path_exists(&path) {
                    push_unique(&mut denied, path);
                }
            }
        } else {
            for path in agent_state_paths(config, &home) {
                push_unique(&mut readwrite, path);
            }
        }

        for path in map_sources(&config.rw_maps, "read-write")? {
            push_unique(&mut readwrite, path);
        }
        for path in map_sources(&config.ro_maps, "read-only")? {
            push_unique(&mut readonly, path);
        }
        for path in &config.overlay_maps {
            if super::path_exists(path) {
                push_unique(&mut readonly, path.clone());
            }
        }
        if let Some(dir) = &config.claude_dir
            && super::path_exists(dir)
        {
            push_unique(&mut readwrite, dir.clone());
        }
        if config.ssh_enabled() {
            let path = home.join(".ssh");
            if path.is_dir() {
                push_unique(&mut readonly, path);
            }
        }
        if config.pictures_enabled() {
            let path = home.join("Pictures");
            if path.is_dir() {
                push_unique(&mut readonly, path);
            }
        }
    } else if !config.rw_maps.is_empty()
        || !config.ro_maps.is_empty()
        || !config.overlay_maps.is_empty()
    {
        output::warn("Extra maps are disabled in lockdown mode");
    }

    for name in [".gitconfig", ".gitignore"] {
        let path = home.join(name);
        if path.is_file() {
            push_unique(&mut readonly, path);
        }
    }
    let git_config = home.join(".config").join("git");
    if git_config.is_dir() {
        push_unique(&mut readonly, git_config);
    }

    if let Some(worktree) =
        super::discover_git_worktree_paths(config, project_dir, false)
    {
        for path in worktree.unique_paths() {
            if lockdown {
                push_unique(&mut readonly, path);
            } else {
                push_unique(&mut readwrite, path);
            }
        }
    }

    let argv = launch_argv(config, project_dir);
    if !lockdown {
        for executable in crate::command::executable_candidates(&config.command)
        {
            if let Some(path) = resolve_executable(executable, project_dir)
                && let Some(parent) = path.parent()
            {
                push_unique(&mut readonly, parent.to_path_buf());
            }
        }
        if let Some(program) = argv.first()
            && let Some(path) = resolve_executable(program, project_dir)
            && let Some(parent) = path.parent()
        {
            push_unique(&mut readonly, parent.to_path_buf());
        }
    }

    for path in expand_mask_patterns(
        &config.deny_paths,
        &config.deny_path_exceptions,
        project_dir,
    ) {
        push_unique(&mut denied, path);
    }
    add_volume_roots(&readwrite, &mut readonly);
    if lockdown || config.private_home_enabled() {
        // BaseContainer grants traversal through project ancestors. Deny each
        // home entry so that traversal does not expose sibling files, while
        // leaving the profile root itself discoverable by Windows tools.
        add_private_home_denials(&home, &readwrite, &readonly, &mut denied)?;
    }

    let path_strings = |paths: Vec<PathBuf>| {
        paths
            .into_iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
    };
    let network = if !lockdown && config.network_enabled() {
        json!({
            "egress": { "default": "allow" },
            "ingress": { "default": "allow", "hostLoopback": "allow" }
        })
    } else {
        json!({
            "egress": { "default": "deny" },
            "ingress": { "default": "deny", "hostLoopback": "deny" }
        })
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let policy = json!({
        "version": "0.8.0-alpha",
        "containerId": format!("ai-jail-{}-{nonce}", std::process::id()),
        "containment": "processcontainer",
        "lifecycle": { "destroyOnExit": true, "preservePolicy": false },
        "process": {
            "cwd": project_dir.to_string_lossy(),
            "env": child_environment(config),
            "timeout": 0
        },
        "filesystem": {
            "readwritePaths": path_strings(readwrite),
            "readonlyPaths": path_strings(readonly),
            "deniedPaths": path_strings(denied)
        },
        "fallback": { "allowDaclMutation": true },
        "network": network,
        "ui": { "disable": false, "clipboard": "none", "injection": false },
        "processContainer": {
            "ui": {
                "isolation": "container",
                "desktopSystemControl": false,
                "systemSettings": "none",
                "ime": false
            }
        }
    });
    Ok((policy, argv))
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let bits = u32::from(chunk[0]) << 16
            | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
            | u32::from(*chunk.get(2).unwrap_or(&0));
        encoded.push(TABLE[((bits >> 18) & 63) as usize] as char);
        encoded.push(TABLE[((bits >> 12) & 63) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            TABLE[((bits >> 6) & 63) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            TABLE[(bits & 63) as usize] as char
        } else {
            '='
        });
    }
    encoded
}

pub fn build(
    guard: &SandboxGuard,
    config: &Config,
    project_dir: &Path,
    verbose: bool,
) -> Result<Command, String> {
    let (policy, argv) = build_policy(config, project_dir)?;
    let json = serde_json::to_vec(&policy).map_err(|error| {
        format!("Failed to serialize Windows policy: {error}")
    })?;
    let encoded = base64(&json);
    let command_chars = encoded.encode_utf16().count()
        + argv
            .iter()
            .map(|arg| arg.encode_utf16().count() + 3)
            .sum::<usize>();
    if command_chars > 30_000 {
        return Err(
            "Windows sandbox policy exceeds the safe command-line size; reduce mapped paths or inherited environment variables"
                .into(),
        );
    }
    if verbose {
        output::verbose(&format!(
            "Windows sandbox: {} read-write, {} read-only, {} denied path(s)",
            policy["filesystem"]["readwritePaths"]
                .as_array()
                .map_or(0, Vec::len),
            policy["filesystem"]["readonlyPaths"]
                .as_array()
                .map_or(0, Vec::len),
            policy["filesystem"]["deniedPaths"]
                .as_array()
                .map_or(0, Vec::len)
        ));
    }
    let mut command = Command::new(&guard.wxc_exec);
    command
        .arg("--config-base64")
        .arg(encoded)
        .arg("--")
        .args(argv);
    Ok(command)
}

pub fn dry_run(
    guard: &SandboxGuard,
    config: &Config,
    project_dir: &Path,
) -> Result<String, String> {
    let (mut policy, argv) = build_policy(config, project_dir)?;
    if let Some(environment) = policy["process"].get_mut("env") {
        let count = environment.as_array().map_or(0, Vec::len);
        *environment = json!([format!("<redacted: {count} variables>")]);
    }
    let policy = serde_json::to_string_pretty(&policy)
        .map_err(|error| format!("Failed to format Windows policy: {error}"))?;
    Ok(format!(
        "{} --config-base64 <policy> -- {}\n{}",
        guard.wxc_exec.display(),
        argv.iter()
            .map(|arg| quote_for_display(arg))
            .collect::<Vec<_>>()
            .join(" "),
        policy
    ))
}

fn quote_for_display(argument: &str) -> String {
    if argument.is_empty()
        || argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        format!("\"{}\"", argument.replace('"', "\\\""))
    } else {
        argument.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
    }

    #[test]
    fn drive_root_is_added_without_exposing_the_volume_recursively() {
        let mut readonly = Vec::new();
        add_volume_roots(&[PathBuf::from(r"C:\work\project")], &mut readonly);
        assert_eq!(readonly, vec![PathBuf::from(r"C:\")]);
    }

    #[test]
    fn private_home_denies_siblings_but_keeps_explicit_grants() {
        let home = std::env::temp_dir()
            .join(format!("ai-jail-home-policy-{}", std::process::id()));
        let state = home.join(".codex");
        let secret = home.join("secret");
        let hive = home.join("NTUSER.DAT");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(&hive, "locked by Windows in a real profile").unwrap();
        let mut denied = Vec::new();
        add_private_home_denials(
            &home,
            std::slice::from_ref(&state),
            &[],
            &mut denied,
        )
        .unwrap();
        assert!(!denied.iter().any(|path| same_path(path, &state)));
        assert!(!denied.iter().any(|path| same_path(path, &hive)));
        assert!(denied.iter().any(|path| same_path(path, &secret)));
        std::fs::remove_dir_all(home).unwrap();
    }
}
