//! Fixed GitHub API purposes through the existing official `gh` client. Only
//! the selected capability enters this child; candidate data cannot choose a
//! host, repository, token, method, or unbounded response.
use crate::{Environment, Result, clean_environment, guards, process};
use serde_json::Value;
use std::{fs, path::Path, time::Duration};

pub const MAX_JSON: usize = 1_048_576;
pub const MAX_RECEIPT: usize = 1_048_576;
pub const MAX_ENVELOPE: usize = 16_384;
pub const MAX_PAGES: usize = 10;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    PublicRead,
    SourceRead,
    ApprovalRead,
    Dispatch,
    HandoffWrite,
    HandoffRead,
    Status,
}
impl Role {
    fn token(self) -> &'static str {
        match self {
            Self::PublicRead | Self::Dispatch => "GITHUB_TOKEN",
            Self::SourceRead => "SOURCE_METADATA_READ_TOKEN",
            Self::ApprovalRead => "SOURCE_CI_APPROVAL_READ_TOKEN",
            Self::HandoffWrite => "SOURCE_CI_HANDOFF_WRITE_TOKEN",
            Self::HandoffRead => "SOURCE_CI_HANDOFF_READ_TOKEN",
            Self::Status => "SOURCE_CI_STATUS_TOKEN",
        }
    }
    fn allows(self, method: &str, endpoint: &str) -> bool {
        let private = "repos/omnisolo-llc/omniterm";
        let public = "repos/omnisolo-llc/omniterm-release";
        if method == "GET" {
            return match self {
                Self::PublicRead | Self::Dispatch => {
                    endpoint == public
                        || endpoint == format!("{public}/git/ref/heads/main")
                        || endpoint.starts_with(&format!("{public}/actions/runs/"))
                        || endpoint
                            .starts_with(&format!("{public}/actions/workflows/source-ci.yml/"))
                }
                Self::SourceRead => {
                    endpoint == private
                        || endpoint == format!("{private}/git/ref/heads/main")
                        || endpoint.starts_with(&format!("{private}/pulls/"))
                        || endpoint.starts_with(&format!("{private}/compare/"))
                        || endpoint
                            .starts_with(&format!("{private}/contents/omniterm-release?ref="))
                        || endpoint.starts_with(&format!(
                            "{private}/contents/scripts/release/public-ci-migration.json?ref="
                        ))
                }
                Self::ApprovalRead => endpoint
                    == format!("{public}/environments/source-ci-authority")
                    || endpoint.starts_with(&format!(
                        "{public}/environments/source-ci-authority/variables/SOURCE_CI_APPROVAL_"
                    ))
                    || endpoint
                        == format!(
                            "{public}/environments/source-ci-discovery/variables/SOURCE_CI_DISCOVERY"
                        ),
                Self::HandoffWrite | Self::HandoffRead => {
                    endpoint == private
                        || endpoint.starts_with(&format!("{private}/releases?"))
                        || endpoint.starts_with(&format!("{private}/releases/"))
                }
                Self::Status => false,
            };
        }
        method == "POST"
            && match self {
                Self::Dispatch => {
                    endpoint == format!("{public}/actions/workflows/source-ci.yml/dispatches")
                }
                Self::Status => endpoint
                    .strip_prefix(&format!("{private}/statuses/"))
                    .is_some_and(crate::input::valid_sha),
                Self::HandoffWrite => {
                    endpoint == format!("{private}/releases")
                        || endpoint.starts_with(
                            "https://uploads.github.com/repos/omnisolo-llc/omniterm/releases/",
                        )
                }
                _ => false,
            }
    }
}
pub trait SourceApi {
    fn get_json(&mut self, endpoint: &str) -> Result<Value>;
    fn post_json(&mut self, endpoint: &str, body: &Value) -> Result<Value>;
    fn upload(&mut self, endpoint: &str, bytes: &[u8]) -> Result<()>;
    fn get_bytes(&mut self, endpoint: &str, maximum: usize) -> Result<Vec<u8>>;
}
/// No Debug implementation: the isolated environment contains one capability.
pub struct GitHubApi {
    role: Role,
    env: Environment,
    work: tempfile::TempDir,
    deadline: Option<u64>,
}
impl GitHubApi {
    pub fn new(parent: &Environment, work: &Path, role: Role) -> Result<Self> {
        guards::directory(work)?;
        let token = parent
            .get(role.token())
            .filter(|t| !t.is_empty() && t.len() <= 8192 && t.bytes().all(|b| b.is_ascii_graphic()))
            .ok_or("Source-CI capability unavailable")?;
        let work = tempfile::tempdir_in(work).map_err(|_| "Source-CI API workspace unavailable")?;
        let mut env = clean_environment(parent);
        env.insert("GH_TOKEN".into(), token.clone());
        env.insert("GH_HOST".into(), "github.com".into());
        env.insert("GH_PROMPT_DISABLED".into(), "1".into());
        env.insert("GH_NO_UPDATE_NOTIFIER".into(), "1".into());
        env.insert(
            "GH_CONFIG_DIR".into(),
            work.path().to_string_lossy().into_owned(),
        );
        Ok(Self {
            role,
            env,
            work,
            deadline: None,
        })
    }
    pub fn set_deadline(&mut self, expires_epoch: u64) -> Result<()> {
        if expires_epoch <= now()? {
            return Err("Source-CI API authority expired");
        }
        self.deadline = Some(expires_epoch);
        Ok(())
    }
    fn request(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<&[u8]>,
        accept: &str,
        max: usize,
    ) -> Result<Vec<u8>> {
        if endpoint.len() > 1024
            || !endpoint.is_ascii()
            || endpoint.bytes().any(|b| b.is_ascii_control() || b == b' ')
            || endpoint.contains(['\\', '#'])
            || endpoint.contains("/../")
            || endpoint.contains("/./")
            || !self.role.allows(method, endpoint)
            || max == 0
            || max > MAX_RECEIPT
        {
            return Err("Source-CI API purpose denied");
        }
        let mut args = vec![
            "api".into(),
            "--hostname".into(),
            "github.com".into(),
            "--method".into(),
            method.into(),
            "--header".into(),
            format!("Accept: {accept}"),
            "--header".into(),
            "X-GitHub-Api-Version: 2022-11-28".into(),
            endpoint.into(),
        ];
        let input = if let Some(bytes) = body {
            if bytes.is_empty() || bytes.len() > MAX_RECEIPT {
                return Err("Source-CI API input exceeds bound");
            }
            let file = tempfile::NamedTempFile::new_in(self.work.path())
                .map_err(|_| "Source-CI API input unavailable")?;
            fs::write(file.path(), bytes).map_err(|_| "Source-CI API input unavailable")?;
            args.extend([
                "--input".into(),
                file.path().to_string_lossy().into_owned(),
                "--header".into(),
                if endpoint.starts_with("https://uploads.github.com/") {
                    "Content-Type: application/octet-stream".into()
                } else {
                    "Content-Type: application/json".into()
                },
            ]);
            Some(file)
        } else {
            None
        };
        let timeout = if let Some(deadline) = self.deadline {
            let remaining = deadline
                .checked_sub(now()?)
                .filter(|s| *s > 0)
                .ok_or("Source-CI API authority expired")?;
            Duration::from_secs(remaining.min(45))
        } else {
            Duration::from_secs(45)
        };
        let result = process::run(
            Path::new("gh"),
            &args,
            self.work.path(),
            &self.env,
            timeout,
            None,
        )
        .map_err(|_| "Source-CI GitHub API unavailable")?;
        drop(input);
        if let Some(deadline) = self.deadline {
            if now()? >= deadline {
                return Err("Source-CI API authority expired");
            }
        }
        if result.len() > max {
            return Err("Source-CI API response exceeds bound");
        }
        Ok(result)
    }
}
impl SourceApi for GitHubApi {
    fn get_json(&mut self, endpoint: &str) -> Result<Value> {
        crate::json::parse(&self.request(
            "GET",
            endpoint,
            None,
            "application/vnd.github+json",
            MAX_JSON,
        )?)
        .map_err(|_| "Invalid Source-CI GitHub metadata")
    }
    fn post_json(&mut self, endpoint: &str, body: &Value) -> Result<Value> {
        let bytes = serde_json::to_vec(body).map_err(|_| "Invalid Source-CI API request")?;
        let response = self.request(
            "POST",
            endpoint,
            Some(&bytes),
            "application/vnd.github+json",
            MAX_JSON,
        )?;
        if response.is_empty() {
            Ok(Value::Null)
        } else {
            crate::json::parse(&response).map_err(|_| "Invalid Source-CI GitHub metadata")
        }
    }
    fn upload(&mut self, endpoint: &str, bytes: &[u8]) -> Result<()> {
        self.request(
            "POST",
            endpoint,
            Some(bytes),
            "application/vnd.github+json",
            MAX_JSON,
        )
        .map(|_| ())
    }
    fn get_bytes(&mut self, endpoint: &str, maximum: usize) -> Result<Vec<u8>> {
        self.request("GET", endpoint, None, "application/octet-stream", maximum)
    }
}
pub fn fields(value: &Value, names: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("Invalid Source-CI object")?;
    if object.len() != names.len() || !names.iter().all(|n| object.contains_key(*n)) {
        return Err("Invalid Source-CI fields");
    }
    Ok(())
}
pub fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
pub fn json_digest(value: &Value) -> Result<String> {
    Ok(digest(
        &serde_json::to_vec(value).map_err(|_| "Invalid Source-CI encoding")?,
    ))
}
pub fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name].as_str().ok_or("Invalid Source-CI text")
}
pub fn number(value: &Value, name: &str) -> Result<u64> {
    value[name].as_u64().ok_or("Invalid Source-CI number")
}
pub fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "Source-CI clock unavailable")?
        .as_secs())
}
pub fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
