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
/// Only OS/tool locations; never implicit credentials or tool injection settings.
pub fn clean_environment(parent: &Environment) -> Environment {
    let mut env: Environment = parent
        .iter()
        .filter(|(k, _)| {
            matches!(
                k.to_ascii_uppercase().as_str(),
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
            )
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
