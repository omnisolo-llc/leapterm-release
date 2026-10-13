use crate::{
    Environment, Result, clean_environment, guards, input::valid_sha, null_device, process,
};
use sha1::{Digest, Sha1};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    time::Duration,
};
const MAX_FILES: usize = 100_000;
#[derive(Debug)]
pub struct Entry {
    pub mode: String,
    pub kind: String,
    pub oid: String,
    pub path: String,
}
pub fn git(root: &Path, args: &[String], env: &Environment) -> Result<Vec<u8>> {
    let mut log = if let Some(path) = env.get("NATIVE_GIT_LOG") {
        let path = Path::new(path);
        let mut options = fs::OpenOptions::new();
        options.append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(path)
            .map_err(|_| "Private Git log unavailable")?;
        guards::single_link(&file)?;
        Some(file)
    } else {
        None
    };
    let mut safe = vec![
        "-c".into(),
        format!("core.hooksPath={}", null_device()),
        "-c".into(),
        "core.fsmonitor=false".into(),
        "-c".into(),
        "credential.helper=".into(),
        "-c".into(),
        "http.followRedirects=false".into(),
        "-c".into(),
        "protocol.allow=never".into(),
        "-c".into(),
        "protocol.https.allow=always".into(),
        "-c".into(),
        "submodule.recurse=false".into(),
        "-c".into(),
        "fetch.recurseSubmodules=false".into(),
    ];
    safe.extend_from_slice(args);
    process::run(
        Path::new("git"),
        &safe,
        root,
        env,
        Duration::from_secs(
            if args
                .iter()
                .any(|a| matches!(a.as_str(), "fetch" | "submodule"))
            {
                900
            } else {
                30
            },
        ),
        log.as_mut(),
    )
}
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}
fn text(bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes).map_err(|_| "Non-UTF8 source metadata")
}
pub fn tree(root: &Path, env: &Environment) -> Result<Vec<Entry>> {
    let bytes = git(root, &strings(&["ls-tree", "-r", "-z", "HEAD"]), env)?;
    let mut entries = Vec::new();
    for raw in bytes.split(|b| *b == 0).filter(|v| !v.is_empty()) {
        let tab = raw
            .iter()
            .position(|b| *b == b'\t')
            .ok_or("Invalid Git tree record")?;
        let fields = std::str::from_utf8(&raw[..tab])
            .map_err(|_| "Invalid Git metadata")?
            .split(' ')
            .collect::<Vec<_>>();
        let path = std::str::from_utf8(&raw[tab + 1..]).map_err(|_| "Non-UTF8 source path")?;
        if fields.len() != 3 || !guards::safe_path(path) || !valid_sha(fields[2]) {
            return Err("Invalid source tree path");
        }
        entries.push(Entry {
            mode: fields[0].into(),
            kind: fields[1].into(),
            oid: fields[2].into(),
            path: path.into(),
        });
        if entries.len() > MAX_FILES {
            return Err("Source tree exceeds bound");
        }
    }
    Ok(entries)
}
pub fn reject_config(root: &Path, env: &Environment) -> Result<()> {
    let bytes = git(
        root,
        &strings(&["config", "--no-includes", "--local", "--null", "--list"]),
        env,
    )?;
    reject_config_bytes(&bytes)
}
fn reject_config_bytes(bytes: &[u8]) -> Result<()> {
    for item in bytes.split(|b| *b == 0).filter(|v| !v.is_empty()) {
        let name = std::str::from_utf8(
            item.split(|b| *b == b'\n')
                .next()
                .ok_or("Invalid Git config")?,
        )
        .map_err(|_| "Invalid Git config")?
        .to_ascii_lowercase();
        if [
            "url.",
            "include.",
            "includeif.",
            "credential.",
            "http.",
            "filter.",
            "diff.",
            "merge.",
            "protocol.",
        ]
        .iter()
        .any(|p| name.starts_with(p))
            || [
                "core.sshcommand",
                "core.gitproxy",
                "core.fsmonitor",
                "core.hookspath",
                "submodule.recurse",
                "fetch.recursesubmodules",
                "extensions.worktreeconfig",
            ]
            .contains(&name.as_str())
            || (name.starts_with("submodule.")
                && [".update", ".recurse", ".fetchrecursesubmodules"]
                    .iter()
                    .any(|s| name.ends_with(s)))
        {
            return Err("Unsafe local source Git configuration");
        }
    }
    Ok(())
}
fn safe_link(root: &Path, path: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(relative) = parent.strip_prefix(root) else {
        return false;
    };
    let mut normalized = PathBuf::from(relative);
    for part in target.components() {
        match part {
            Component::ParentDir => {
                if !normalized.pop() {
                    return false;
                }
            }
            Component::Normal(p) => normalized.push(p),
            Component::CurDir => {}
            _ => return false,
        }
    }
    let mut candidate = root.join(normalized);
    while !candidate.exists() {
        if !candidate.pop() {
            return false;
        }
    }
    candidate.canonicalize().is_ok_and(|p| p.starts_with(root))
}
fn digest_file(path: &Path, len: u64) -> Result<String> {
    if len > 1024 * 1024 * 1024 {
        return Err("Source file exceeds bound");
    }
    let mut digest = Sha1::new();
    digest.update(format!("blob {len}\0").as_bytes());
    // Empty tracked blobs are legal; the regular-file guard otherwise rejects empties.
    let mut file = guards::open_regular_bounded(path, 1024 * 1024 * 1024, true)?;
    let before = file.metadata().map_err(|_| "Source file unavailable")?;
    let mut bytes = [0u8; 65536];
    let mut read = 0u64;
    loop {
        let n = file
            .read(&mut bytes)
            .map_err(|_| "Source file cannot be read")?;
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > len {
            return Err("Source changed during verification");
        }
        digest.update(&bytes[..n]);
    }
    if read != len {
        return Err("Source changed during verification");
    }
    guards::unchanged(&file, path)?;
    if !guards::same(
        &before,
        &fs::symlink_metadata(path).map_err(|_| "Source file unavailable")?,
    ) {
        return Err("Source changed during verification");
    }
    Ok(format!("{:x}", digest.finalize()))
}
pub fn verify_source(root: &Path, sha: &str) -> Result<()> {
    let env = clean_environment(&std::env::vars().collect());
    verify(
        &root.canonicalize().map_err(|_| "Source root missing")?,
        sha,
        &env,
        false,
        0,
    )
}
pub fn verify_tools(root: &Path, env: &Environment) -> Result<()> {
    use std::collections::BTreeSet;
    let mut expected = BTreeSet::new();
    let mut tree_bytes = 0;
    for entry in tree(root, env)?
        .iter()
        .filter(|e| e.path.starts_with("tools/"))
    {
        tree_bytes += entry.path.len() + 64;
        if tree_bytes > 1024 * 1024 {
            return Err("Reviewed native tree metadata exceeds bound");
        }
        if entry.kind != "blob" || !["100644", "100755"].contains(&entry.mode.as_str()) {
            return Err("Native tooling must be regular committed files");
        }
        expected.insert(entry.path.clone());
    }
    if expected.is_empty() {
        return Err("Pinned native tooling is missing");
    }
    let mut actual = BTreeSet::new();
    let mut pending = vec![root.join("tools")];
    while let Some(path) = pending.pop() {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "Native tooling escapes source")?
            .to_str()
            .ok_or("Invalid native tool path")?
            .replace('\\', "/");
        if !guards::safe_path(&relative) {
            return Err("Invalid native tool path");
        }
        let info = fs::symlink_metadata(&path).map_err(|_| "Native tooling unavailable")?;
        if guards::reparse(&info) {
            return Err("Native tool symlinks are forbidden");
        }
        if info.is_dir() {
            if relative != "tools"
                && !expected
                    .iter()
                    .any(|p| p.starts_with(&format!("{relative}/")))
            {
                return Err("Unreviewed native tool directory");
            }
            for child in fs::read_dir(path).map_err(|_| "Native tooling unavailable")? {
                pending.push(child.map_err(|_| "Native tooling unavailable")?.path());
            }
        } else if info.is_file() {
            actual.insert(relative);
            if actual.len() > 1024 {
                return Err("Native tool inventory exceeds bound");
            }
        } else {
            return Err("Unsafe native tooling type");
        }
        if pending.len() > 2048 {
            return Err("Native tool inventory exceeds bound");
        }
    }
    if actual != expected {
        return Err("Unreviewed native compiler input");
    }
    Ok(())
}
pub fn resolve_revision(root: &Path, requested: &str, env: &Environment) -> Result<String> {
    let tip = text(git(
        root,
        &strings(&["rev-parse", "refs/remotes/origin/reviewed"]),
        env,
    )?)?
    .trim()
    .to_owned();
    let sha = if requested.is_empty() {
        tip
    } else {
        requested.into()
    };
    if !valid_sha(&sha) {
        return Err("Invalid source revision");
    }
    git(
        root,
        &strings(&[
            "merge-base",
            "--is-ancestor",
            &sha,
            "refs/remotes/origin/reviewed",
        ]),
        env,
    )?;
    Ok(sha)
}
pub fn verify(
    root: &Path,
    sha: &str,
    env: &Environment,
    allow_empty: bool,
    depth: usize,
) -> Result<()> {
    if depth > 20
        || !valid_sha(sha)
        || guards::reparse(&fs::symlink_metadata(root).map_err(|_| "Source root missing")?)
    {
        return Err("Unsafe source root or revision");
    }
    let root = root.canonicalize().map_err(|_| "Source root missing")?;
    let actual_root = text(git(
        &root,
        &strings(&["rev-parse", "--show-toplevel"]),
        env,
    )?)?;
    if Path::new(actual_root.trim())
        .canonicalize()
        .map_err(|_| "Git root missing")?
        != root
    {
        return Err("Source is not an initialized Git root");
    }
    reject_config(&root, env)?;
    if text(git(
        &root,
        &strings(&["rev-parse", "--verify", "HEAD"]),
        env,
    )?)?
    .trim()
        != sha
    {
        return Err("Source revision differs from request");
    }
    if !git(
        &root,
        &strings(&["for-each-ref", "--format=%(refname)", "refs/replace/"]),
        env,
    )?
    .is_empty()
    {
        return Err("Source replacement refs forbidden");
    }
    git(
        &root,
        &strings(&[
            "diff-index",
            "--cached",
            "--quiet",
            "--no-ext-diff",
            "HEAD",
            "--",
        ]),
        env,
    )?;
    let common = text(git(
        &root,
        &strings(&["rev-parse", "--git-common-dir"]),
        env,
    )?)?;
    let common = PathBuf::from(common.trim());
    let common = if common.is_absolute() {
        common
    } else {
        root.join(common)
    }
    .canonicalize()
    .map_err(|_| "Source metadata missing")?;
    for entry in tree(&root, env)? {
        let path = root.join(&entry.path);
        let mut parent = root.clone();
        let components: Vec<_> = entry.path.split('/').collect();
        for part in &components[..components.len() - 1] {
            parent.push(part);
            let info = fs::symlink_metadata(&parent).map_err(|_| "Source parent missing")?;
            if !info.is_dir() || guards::reparse(&info) {
                return Err("Unsafe source parent");
            }
        }
        if entry.mode == "160000" && entry.kind == "commit" {
            let info = match fs::symlink_metadata(&path) {
                Ok(info) => info,
                Err(error) if allow_empty && error.kind() == std::io::ErrorKind::NotFound => {
                    continue;
                }
                Err(_) => return Err("Pinned submodule missing"),
            };
            if !info.is_dir() || guards::reparse(&info) {
                return Err("Unsafe submodule directory");
            }
            if allow_empty && fs::read_dir(&path).is_ok_and(|mut r| r.next().is_none()) {
                continue;
            }
            let child_common = text(git(
                &path,
                &strings(&["rev-parse", "--git-common-dir"]),
                env,
            )?)?;
            let child_common = PathBuf::from(child_common.trim());
            let child_common = if child_common.is_absolute() {
                child_common
            } else {
                path.join(child_common)
            };
            if child_common
                .canonicalize()
                .map_err(|_| "Submodule metadata missing")?
                != common
                    .join("modules")
                    .join(&entry.path)
                    .canonicalize()
                    .map_err(|_| "Submodule metadata outside parent")?
            {
                return Err("Submodule metadata outside parent");
            }
            verify(&path, &entry.oid, env, allow_empty, depth + 1)?;
            continue;
        }
        let info = fs::symlink_metadata(&path).map_err(|_| "Committed source file missing")?;
        let digest = if entry.mode == "120000" {
            if !info.file_type().is_symlink() {
                return Err("Committed symlink type changed");
            }
            let target = fs::read_link(&path).map_err(|_| "Invalid source link")?;
            if !safe_link(&root, &path, &target) {
                return Err("Source symlink escapes root");
            }
            let bytes = target.to_str().ok_or("Non-UTF8 source link")?.as_bytes();
            let mut hash = Sha1::new();
            hash.update(format!("blob {}\0", bytes.len()));
            hash.update(bytes);
            format!("{:x}", hash.finalize())
        } else {
            if entry.kind != "blob"
                || !["100644", "100755"].contains(&entry.mode.as_str())
                || !info.is_file()
                || guards::reparse(&info)
            {
                return Err("Committed source type changed");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if (info.permissions().mode() & 0o100 != 0) != (entry.mode == "100755") {
                    return Err("Committed source mode changed");
                }
            }
            digest_file(&path, info.len())?
        };
        if digest != entry.oid {
            return Err("Source bytes differ from pinned commit");
        }
    }
    if !git(
        &root,
        &strings(&["ls-files", "--others", "--exclude-standard", "-z"]),
        env,
    )?
    .is_empty()
    {
        return Err("Untracked files cannot be release inputs");
    }
    Ok(())
}
pub const PUBLIC_URL: &str = "https://github.com/omnisolo-llc/omniterm-release.git";
pub const WEBSITE_URL: &str = "https://github.com/omnisolo-llc/omniterm-website.git";
pub fn materialize(
    root: &Path,
    sha: &str,
    builder: &str,
    token: &str,
    env: &Environment,
) -> Result<()> {
    materialize_scoped(root, sha, Some(builder), token, None, env)
}
pub fn materialize_scoped(
    root: &Path,
    sha: &str,
    builder: Option<&str>,
    token: &str,
    website_ssh: Option<&Environment>,
    env: &Environment,
) -> Result<()> {
    use base64::Engine;
    verify(root, sha, env, true, 0)?;
    let entries = tree(root, env)?;
    let links: Vec<_> = entries.iter().filter(|e| e.mode == "160000").collect();
    if builder.is_some_and(|builder| {
        !links
            .iter()
            .any(|e| e.path == "omniterm-release" && e.oid == builder)
    }) {
        return Err("Source builder pin differs from executing builder");
    }
    let metadata = git(
        root,
        &strings(&[
            "config",
            "--no-includes",
            "--null",
            "--blob",
            "HEAD:.gitmodules",
            "--list",
        ]),
        env,
    )?;
    let mut fields = std::collections::BTreeMap::new();
    for raw in metadata.split(|b| *b == 0).filter(|v| !v.is_empty()) {
        let text = std::str::from_utf8(raw).map_err(|_| "Invalid submodule metadata")?;
        let (name, value) = text.split_once('\n').ok_or("Invalid submodule metadata")?;
        if fields.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err("Duplicate submodule metadata");
        }
    }
    if fields.len() != links.len() * 2 {
        return Err("Unapproved submodule metadata");
    }
    for link in links {
        let url = match link.path.as_str() {
            "omniterm-release" => PUBLIC_URL,
            "omniterm-website" => WEBSITE_URL,
            _ => return Err("Unapproved submodule destination"),
        };
        if fields.get(&format!("submodule.{}.path", link.path)) != Some(&link.path)
            || fields
                .get(&format!("submodule.{}.url", link.path))
                .map(String::as_str)
                != Some(url)
        {
            return Err("Submodule identity differs from allowlist");
        }
        // Cached submodule metadata can survive deinitialization. Check it before Git fetches.
        let common = text(git(
            root,
            &strings(&["rev-parse", "--git-common-dir"]),
            env,
        )?)?;
        let common_path = PathBuf::from(common.trim());
        let common_path = if common_path.is_absolute() {
            common_path
        } else {
            root.join(common_path)
        };
        let mut cache = common_path;
        for component in ["modules", link.path.as_str()] {
            cache.push(component);
            match fs::symlink_metadata(&cache) {
                Ok(info) if guards::reparse(&info) || !info.is_dir() => {
                    return Err("Unsafe submodule cache directory");
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("Submodule cache unavailable"),
            }
        }
        let config = cache.join("config");
        if let Ok(info) = fs::symlink_metadata(&config) {
            if !info.is_file() || guards::reparse(&info) || info.len() > 65536 {
                return Err("Unsafe submodule cache configuration");
            }
            let config_text = config.to_str().ok_or("Non-UTF8 submodule metadata path")?;
            let bytes = git(
                root,
                &strings(&[
                    "config",
                    "--no-includes",
                    "--null",
                    "--file",
                    config_text,
                    "--list",
                ]),
                env,
            )?;
            reject_config_bytes(&bytes)?;
            for record in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
                let record =
                    std::str::from_utf8(record).map_err(|_| "Invalid submodule configuration")?;
                let (key, value) = record
                    .split_once('\n')
                    .ok_or("Invalid submodule configuration")?;
                if key.starts_with("remote.")
                    && key.ends_with(".url")
                    && (key != "remote.origin.url" || value != url)
                {
                    return Err("Unapproved cached submodule remote");
                }
            }
        }
        let mut scoped = env.clone();
        let mut transport_url = url;
        if url == WEBSITE_URL && website_ssh.is_some() {
            scoped = website_ssh.ok_or("Submodule transport missing")?.clone();
            transport_url = "ssh://git@ssh.github.com:443/omnisolo-llc/omniterm-website.git";
        } else if url == WEBSITE_URL {
            if !(16..=4096).contains(&token.len())
                || !token.bytes().all(|b| (0x21..=0x7e).contains(&b))
            {
                return Err("Private submodule credential is missing or malformed");
            }
            let value =
                base64::engine::general_purpose::STANDARD.encode(format!("x-access-token:{token}"));
            scoped.insert("GIT_CONFIG_COUNT".into(), "1".into());
            scoped.insert("GIT_CONFIG_KEY_0".into(), format!("http.{url}.extraheader"));
            scoped.insert(
                "GIT_CONFIG_VALUE_0".into(),
                format!("AUTHORIZATION: basic {value}"),
            );
        }
        git(
            root,
            &strings(&["submodule", "sync", "--", &link.path]),
            env,
        )?;
        git(
            root,
            &[
                "-c".into(),
                format!("submodule.{}.url={transport_url}", link.path),
                "-c".into(),
                if website_ssh.is_some() && url == WEBSITE_URL {
                    "protocol.ssh.allow=always".into()
                } else {
                    "protocol.ssh.allow=never".into()
                },
                "-c".into(),
                format!("submodule.{}.update=checkout", link.path),
                "submodule".into(),
                "update".into(),
                "--init".into(),
                "--checkout".into(),
                "--".into(),
                link.path.clone(),
            ],
            &scoped,
        )?;
    }
    verify(root, sha, env, false, 0)
}
