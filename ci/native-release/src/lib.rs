pub mod agent;
pub mod ci_request;
pub mod guards;
pub mod hosted_inputs;
pub mod input;
pub mod json;
pub mod launch;
pub mod prerequisites;
pub mod process;
pub mod publication_candidates;
pub mod retained_artifacts;
pub mod runner_policy;
pub mod source;
pub mod source_api;
pub mod source_ci;
pub mod source_discovery;
pub mod source_handoff;
pub mod source_report;
pub mod windows_sdk;
pub type Environment = std::collections::BTreeMap<String, String>;
pub type Result<T> = std::result::Result<T, &'static str>;
pub use input::{validate_authority, validate_request};
pub use source::verify_source;
fn safe_cache_directory(value: &str) -> bool {
    if value.is_empty() || value.chars().any(char::is_control) {
        return false;
    }
    let path = std::path::Path::new(value);
    if !path.is_absolute()
        || !path.components().all(|part| {
            matches!(
                part,
                std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
                    | std::path::Component::Normal(_)
            )
        })
    {
        return false;
    }
    let mut saw_existing = false;
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                if !meta.is_dir() || guards::reparse(&meta) {
                    return false;
                }
                saw_existing = true;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && !saw_existing => continue,
            Err(_) => return false,
        }
    }
    saw_existing
}
fn safe_cache_file(value: &str) -> bool {
    if value.is_empty() || value.chars().any(char::is_control) {
        return false;
    }
    let path = std::path::Path::new(value);
    if !path.is_absolute()
        || !path.components().all(|part| {
            matches!(
                part,
                std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
                    | std::path::Component::Normal(_)
            )
        })
    {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    safe_cache_directory(parent.to_str().unwrap_or(""))
}
fn safe_compiler_wrapper(value: &str) -> bool {
    if value.is_empty() || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if matches!(value, "sccache" | "ccache" | "sccache.exe" | "ccache.exe") {
        return true;
    }
    let path = std::path::Path::new(value);
    if !path.is_absolute()
        || !path.components().all(|part| {
            matches!(
                part,
                std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
                    | std::path::Component::Normal(_)
            )
        })
    {
        return false;
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_file() || guards::reparse(&meta) {
        return false;
    }
    path.ancestors().skip(1).all(|ancestor| {
        std::fs::symlink_metadata(ancestor)
            .is_ok_and(|info| info.is_dir() && !guards::reparse(&info))
    })
}
/// Only OS/tool locations; never implicit credentials or tool injection settings.
pub fn clean_environment(parent: &Environment) -> Environment {
    let mut env: Environment = parent
        .iter()
        .filter(|(k, v)| {
            if v.contains('\0') {
                return false;
            }
            match k.to_ascii_uppercase().as_str() {
                "PATH"
                | "HOME"
                | "USER"
                | "LOGNAME"
                | "TMP"
                | "TEMP"
                | "TMPDIR"
                | "SYSTEMROOT"
                | "SYSTEMDRIVE"
                | "WINDIR"
                | "USERPROFILE"
                | "LANG"
                | "LC_ALL"
                | "RUSTUP_HOME"
                | "JAVA_HOME"
                | "ANDROID_HOME"
                | "ANDROID_SDK_ROOT"
                | "DEVELOPER_DIR"
                | "SDKROOT"
                | "NUMBER_OF_PROCESSORS"
                | "PROGRAMFILES"
                | "PROGRAMFILES(X86)"
                | "PROGRAMDATA"
                | "PROGRAMW6432"
                | "COMSPEC"
                | "LOCALAPPDATA"
                | "APPDATA"
                | "COMMONPROGRAMFILES"
                | "COMMONPROGRAMFILES(X86)" => true,
                "SCCACHE_DIR"
                | "FLUTTER_SDK_CACHE_DIR"
                | "PUB_CACHE_DIR"
                | "ANDROID_NDK_CACHE_DIR"
                | "LEAP_MOBILE_FREERDP_CACHE_DIR"
                | "LEAP_MOBILE_SDK_ARCHIVES_DIR" => safe_cache_directory(v),
                "SCCACHE_CONF" | "SCCACHE_CACHED_CONF" => safe_cache_file(v),
                "RUSTC_WRAPPER" | "CARGO_BUILD_RUSTC_WRAPPER" | "LEAP_C_COMPILER_LAUNCHER" => {
                    safe_compiler_wrapper(v)
                }
                _ => false,
            }
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (key, value) in [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_SYSTEM", std::env::consts::OS),
        ("GIT_CONFIG_GLOBAL", std::env::consts::OS),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ] {
        env.insert(
            key.into(),
            if key == "GIT_CONFIG_SYSTEM" || key == "GIT_CONFIG_GLOBAL" {
                null_device().into()
            } else {
                value.into()
            },
        );
    }
    env
}
pub fn null_device() -> &'static str {
    if cfg!(windows) { "NUL" } else { "/dev/null" }
}

pub mod private_final_archive;
