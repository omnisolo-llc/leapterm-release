use omni_release_launcher::{Environment, validate_authority, validate_request, verify_source};
use std::{fs, path::Path, process::Command};
fn request() -> serde_json::Value {
    serde_json::json!({"build_only":true,"verify_target":"ios","source_sha":"a".repeat(40),"version":"1.0.0","build_number":"1005","ios_action":"skip","automatic_release":false,"include_selfhost":true,"preview_windows_self_sign":false})
}
fn authority() -> Environment {
    Environment::from([
        ("GITHUB_ACTIONS".into(), "true".into()),
        ("GITHUB_EVENT_NAME".into(), "workflow_dispatch".into()),
        (
            "GITHUB_REPOSITORY".into(),
            "omnisolo-llc/omniterm-release".into(),
        ),
        ("GITHUB_REF".into(), "refs/heads/main".into()),
        (
            "GITHUB_WORKFLOW_REF".into(),
            "omnisolo-llc/omniterm-release/.github/workflows/release.yml@refs/heads/main".into(),
        ),
        ("GITHUB_SHA".into(), "b".repeat(40)),
        ("GITHUB_RUN_ID".into(), "15".into()),
        ("GITHUB_RUN_ATTEMPT".into(), "1".into()),
        ("SOURCE_REPOSITORY".into(), "omnisolo-llc/omniterm".into()),
        ("SOURCE_BRANCH".into(), "main".into()),
    ])
}
#[test]
fn accepts_explicit_ios_compile_requests() {
    validate_request(&request().to_string()).unwrap();
}
#[test]
fn rejects_invalid_distribution_unknown_and_duplicate_fields() {
    let base = request();
    for (key, value) in [
        ("ios_action", serde_json::json!("upload")),
        ("automatic_release", serde_json::json!(true)),
        ("verify_target", serde_json::json!("docker")),
        ("unexpected", serde_json::json!("x")),
        ("build_only", serde_json::json!("true")),
    ] {
        let mut data = base.clone();
        data[key] = value;
        assert!(validate_request(&data.to_string()).is_err(), "{key}");
    }
    assert!(
        validate_request(r#"{"build_only":true,"build_only":false,"build_number":"1"}"#).is_err()
    );
}
#[test]
fn rejects_noncanonical_release_identity() {
    for (key, value) in [
        ("source_sha", "abc"),
        ("source_sha", "0000000000000000000000000000000000000000"),
        ("version", "01.0.0"),
        ("version", "1.0.0;command"),
        ("build_number", "0"),
        ("build_number", "10000"),
        ("build_number", "1\nEVIL=x"),
    ] {
        let mut data = request();
        data[key] = value.into();
        assert!(validate_request(&data.to_string()).is_err(), "{key}");
    }
}
#[test]
fn workflow_identity_cannot_be_forged_by_alternate_repos_or_refs() {
    validate_authority(&authority()).unwrap();
    for (key, value) in [
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REPOSITORY", "fork/omniterm-release"),
        ("GITHUB_REF", "refs/heads/other"),
        ("SOURCE_REPOSITORY", "other/private"),
        ("SOURCE_BRANCH", "other"),
        ("GITHUB_RUN_ID", "0"),
        (
            "GITHUB_WORKFLOW_REF",
            "omnisolo-llc/omniterm-release/.github/workflows/other.yml@refs/heads/main",
        ),
    ] {
        let mut env = authority();
        env.insert(key.into(), value.into());
        assert!(validate_authority(&env).is_err(), "{key}");
    }
}
fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            &format!("core.hooksPath={}", omni_release_launcher::null_device()),
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", omni_release_launcher::null_device())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn repo() -> (tempfile::TempDir, String) {
    let temp = tempfile::tempdir().unwrap();
    git(temp.path(), &["init", "-q"]);
    git(temp.path(), &["config", "user.name", "Contract"]);
    git(
        temp.path(),
        &["config", "user.email", "contract@example.invalid"],
    );
    fs::write(temp.path().join("payload.txt"), "reviewed bytes\n").unwrap();
    git(temp.path(), &["add", "payload.txt"]);
    git(temp.path(), &["commit", "-qm", "fixture"]);
    let sha = git(temp.path(), &["rev-parse", "HEAD"]);
    (temp, sha)
}
#[test]
fn clean_real_git_tree_passes_byte_verification() {
    let (root, sha) = repo();
    verify_source(root.path(), &sha).unwrap();
}
#[test]
fn changed_bytes_are_rejected_even_with_assume_unchanged() {
    let (root, sha) = repo();
    git(
        root.path(),
        &["update-index", "--assume-unchanged", "payload.txt"],
    );
    fs::write(root.path().join("payload.txt"), "hostile bytes\n").unwrap();
    assert!(verify_source(root.path(), &sha).is_err());
}
#[test]
fn staged_and_untracked_changes_are_rejected() {
    let (root, sha) = repo();
    fs::write(root.path().join("extra.txt"), "extra").unwrap();
    assert!(verify_source(root.path(), &sha).is_err());
    git(root.path(), &["add", "extra.txt"]);
    assert!(verify_source(root.path(), &sha).is_err());
}
#[test]
fn foreign_source_and_local_config_rewrite_fail_closed() {
    let (root, sha) = repo();
    assert!(verify_source(root.path(), &"d".repeat(40)).is_err());
    git(
        root.path(),
        &[
            "config",
            "url.https://attacker.example/.insteadOf",
            "https://github.com/",
        ],
    );
    assert!(verify_source(root.path(), &sha).is_err());
}
#[test]
#[cfg(unix)]
fn file_symlink_cannot_replace_committed_regular_file() {
    let (root, sha) = repo();
    fs::remove_file(root.path().join("payload.txt")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.path().join("payload.txt")).unwrap();
    assert!(verify_source(root.path(), &sha).is_err());
}

#[test]
fn executable_verifies_real_source_without_workflow_or_python() {
    let (root, sha) = repo();
    let output = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .args([
            "verify-source",
            "--root",
            root.path().to_str().unwrap(),
            "--sha",
            &sha,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Verified"));
}
#[test]
fn resolver_refuses_untrusted_invocation_without_touching_credentials() {
    let output = Command::new(env!("CARGO_BIN_EXE_omni-release-launcher"))
        .arg("resolve")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("authority"));
}
#[test]
fn source_link_may_not_escape_even_when_committed() {
    #[cfg(unix)]
    {
        let (root, _) = repo();
        std::os::unix::fs::symlink("/etc/passwd", root.path().join("escape")).unwrap();
        git(root.path(), &["add", "escape"]);
        git(root.path(), &["commit", "-qm", "unsafe link fixture"]);
        let sha = git(root.path(), &["rev-parse", "HEAD"]);
        assert!(verify_source(root.path(), &sha).is_err());
    }
}
#[test]
fn resolved_inputs_must_equal_original_request() {
    let raw = request().to_string();
    let mut parsed = omni_release_launcher::input::Request::parse(&raw).unwrap();
    assert!(
        parsed
            .resolve_from(&Environment::from([(
                "RESOLVED_BUILD_NUMBER".into(),
                "99".into()
            )]))
            .is_err()
    );
    assert!(
        parsed
            .resolve_from(&Environment::from([(
                "RESOLVED_SOURCE_SHA".into(),
                "c".repeat(40)
            )]))
            .is_err()
    );
}
#[test]
fn no_build_process_can_inherit_credentials_or_tool_injection() {
    let parent = Environment::from([
        ("PATH".into(), "/trusted/bin".into()),
        ("SOURCE_DEPLOY_KEY".into(), "secret".into()),
        ("SOURCE_SUBMODULE_TOKEN".into(), "secret".into()),
        ("CARGO_HOME".into(), "/credential-cache".into()),
        ("GIT_CONFIG_COUNT".into(), "2".into()),
        ("BASH_ENV".into(), "evil".into()),
        ("GITHUB_OUTPUT".into(), "/command".into()),
    ]);
    let clean = omni_release_launcher::clean_environment(&parent);
    assert_eq!(clean["PATH"], "/trusted/bin");
    for key in [
        "SOURCE_DEPLOY_KEY",
        "SOURCE_SUBMODULE_TOKEN",
        "CARGO_HOME",
        "GIT_CONFIG_COUNT",
        "BASH_ENV",
        "GITHUB_OUTPUT",
    ] {
        assert!(!clean.contains_key(key), "{key}");
    }
}

fn submodule_repo() -> (tempfile::TempDir, String, String) {
    let (root, _) = repo();
    let (seed, child_sha) = repo();
    for (name, url) in [
        (
            "omniterm-release",
            omni_release_launcher::source::PUBLIC_URL,
        ),
        (
            "omniterm-website",
            omni_release_launcher::source::WEBSITE_URL,
        ),
    ] {
        git(
            root.path(),
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                seed.path().to_str().unwrap(),
                name,
            ],
        );
        git(
            root.path(),
            &[
                "config",
                "--file",
                ".gitmodules",
                &format!("submodule.{name}.url"),
                url,
            ],
        );
    }
    git(
        root.path(),
        &["add", ".gitmodules", "omniterm-release", "omniterm-website"],
    );
    git(root.path(), &["commit", "-qm", "pinned submodule fixture"]);
    let sha = git(root.path(), &["rev-parse", "HEAD"]);
    for name in ["omniterm-release", "omniterm-website"] {
        git(
            &root.path().join(name),
            &[
                "remote",
                "set-url",
                "origin",
                if name == "omniterm-release" {
                    omni_release_launcher::source::PUBLIC_URL
                } else {
                    omni_release_launcher::source::WEBSITE_URL
                },
            ],
        );
        git(root.path(), &["submodule", "deinit", "-f", "--", name]);
    }
    (root, sha, child_sha)
}
#[test]
fn real_cached_submodules_materialize_at_exact_commits_without_network() {
    let (root, sha, builder) = submodule_repo();
    let env = omni_release_launcher::clean_environment(&std::env::vars().collect());
    omni_release_launcher::source::materialize(
        root.path(),
        &sha,
        &builder,
        "local-fixture-read-token",
        &env,
    )
    .unwrap();
    verify_source(root.path(), &sha).unwrap();
    for name in ["omniterm-release", "omniterm-website"] {
        assert_eq!(
            git(&root.path().join(name), &["rev-parse", "HEAD"]),
            builder
        );
        assert_eq!(
            fs::read(root.path().join(name).join("payload.txt")).unwrap(),
            b"reviewed bytes\n"
        );
    }
}
#[test]
fn executing_builder_must_match_source_gitlink_before_acquisition() {
    let (root, sha, _) = submodule_repo();
    let env = omni_release_launcher::clean_environment(&std::env::vars().collect());
    assert!(
        omni_release_launcher::source::materialize(
            root.path(),
            &sha,
            &"f".repeat(40),
            "local-fixture-read-token",
            &env
        )
        .is_err()
    );
    assert!(!root.path().join("omniterm-release/payload.txt").exists());
}
#[test]
fn dangling_gitlink_symlink_cannot_be_treated_as_uninitialized() {
    #[cfg(unix)]
    {
        let (root, sha, _) = submodule_repo();
        let link = root.path().join("omniterm-website");
        fs::remove_dir(&link).unwrap();
        std::os::unix::fs::symlink("/nonexistent-untrusted-location", link).unwrap();
        let env = omni_release_launcher::clean_environment(&std::env::vars().collect());
        assert!(omni_release_launcher::source::verify(root.path(), &sha, &env, true, 0).is_err());
    }
}
#[test]
fn cached_uninitialized_submodule_config_is_checked_before_fetch() {
    let (root, sha, builder) = submodule_repo();
    git(
        root.path(),
        &[
            "config",
            "--file",
            ".git/modules/omniterm-website/config",
            "url.https://attacker.example/.insteadOf",
            "https://github.com/",
        ],
    );
    let env = omni_release_launcher::clean_environment(&std::env::vars().collect());
    assert!(
        omni_release_launcher::source::materialize(
            root.path(),
            &sha,
            &builder,
            "local-fixture-read-token",
            &env
        )
        .is_err()
    );
    assert!(
        !root.path().join("omniterm-website/payload.txt").exists(),
        "Private checkout happened before unsafe cache rejection"
    );
}
#[test]
fn hidden_index_flags_empty_hardlinks_replacement_refs_and_dangerous_config_are_rejected() {
    for flag in ["--skip-worktree", "--assume-unchanged"] {
        let (root, sha) = repo();
        git(root.path(), &["update-index", flag, "payload.txt"]);
        fs::write(root.path().join("payload.txt"), "tampered").unwrap();
        assert!(verify_source(root.path(), &sha).is_err());
    }
    let (root, _) = repo();
    fs::write(root.path().join("empty"), b"").unwrap();
    git(root.path(), &["add", "empty"]);
    git(root.path(), &["commit", "-qm", "empty fixture"]);
    let sha = git(root.path(), &["rev-parse", "HEAD"]);
    verify_source(root.path(), &sha).unwrap();
    fs::hard_link(
        root.path().join("empty"),
        root.path().join(".git/empty-hardlink"),
    )
    .unwrap();
    assert!(verify_source(root.path(), &sha).is_err());
    for key in [
        "core.fsmonitor",
        "core.hooksPath",
        "core.sshCommand",
        "extensions.worktreeConfig",
        "include.path",
        "filter.evil.clean",
        "http.extraheader",
        "submodule.omniterm-website.update",
    ] {
        let (root, sha) = repo();
        git(
            root.path(),
            &[
                "config",
                key,
                if key == "extensions.worktreeConfig" {
                    "true"
                } else {
                    "untrusted"
                },
            ],
        );
        assert!(verify_source(root.path(), &sha).is_err(), "{key}");
    }
    let (root, sha) = repo();
    git(root.path(), &["replace", &sha, &sha]);
    assert!(verify_source(root.path(), &sha).is_err());
}
#[test]
fn cached_submodule_remote_cannot_redirect_a_pinned_fetch() {
    let (root, sha, builder) = submodule_repo();
    git(
        root.path(),
        &[
            "config",
            "--file",
            ".git/modules/omniterm-website/config",
            "remote.origin.url",
            "https://attacker.invalid/website.git",
        ],
    );
    let env = omni_release_launcher::clean_environment(&std::env::vars().collect());
    assert!(
        omni_release_launcher::source::materialize(
            root.path(),
            &sha,
            &builder,
            "local-fixture-read-token",
            &env
        )
        .is_err()
    );
    assert!(!root.path().join("omniterm-website/payload.txt").exists());
}
#[test]
fn ignored_native_compiler_input_is_rejected_before_building() {
    let (root, _) = repo();
    let tools = root.path().join("tools");
    fs::create_dir(&tools).unwrap();
    fs::write(tools.join("main.rs"), "reviewed").unwrap();
    fs::write(root.path().join(".gitignore"), "*.rs\n").unwrap();
    git(root.path(), &["add", ".gitignore"]);
    git(root.path(), &["add", "-f", "tools/main.rs"]);
    git(root.path(), &["commit", "-qm", "native fixture"]);
    let env = omni_release_launcher::clean_environment(&std::env::vars().collect());
    omni_release_launcher::source::verify_tools(root.path(), &env).unwrap();
    fs::write(tools.join("ignored.rs"), "unreviewed").unwrap();
    assert!(omni_release_launcher::source::verify_tools(root.path(), &env).is_err());
}
#[test]
fn actual_ref_resolution_preserves_explicit_ancestors_and_refuses_nonancestors() {
    let (root, ancestor) = repo();
    git(
        root.path(),
        &["update-ref", "refs/remotes/origin/reviewed", &ancestor],
    );
    let env = omni_release_launcher::clean_environment(&std::env::vars().collect());
    assert_eq!(
        omni_release_launcher::source::resolve_revision(root.path(), "", &env).unwrap(),
        ancestor
    );
    fs::write(root.path().join("next"), "later unapproved commit").unwrap();
    git(root.path(), &["add", "next"]);
    git(root.path(), &["commit", "-qm", "descendant fixture"]);
    let descendant = git(root.path(), &["rev-parse", "HEAD"]);
    assert!(
        omni_release_launcher::source::resolve_revision(root.path(), &descendant, &env).is_err()
    );
    git(
        root.path(),
        &["update-ref", "refs/remotes/origin/reviewed", &descendant],
    );
    assert_eq!(
        omni_release_launcher::source::resolve_revision(root.path(), &ancestor, &env).unwrap(),
        ancestor
    );
    assert_eq!(
        omni_release_launcher::source::resolve_revision(root.path(), "", &env).unwrap(),
        descendant
    );
}
#[test]
#[cfg(unix)]
fn committed_mode_changes_and_root_aliases_keep_integrity_checks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (root, sha) = repo();
    let alias = root.path().parent().unwrap().join(format!(
        "alias-{}",
        root.path().file_name().unwrap().to_str().unwrap()
    ));
    symlink(root.path(), &alias).unwrap();
    verify_source(&alias, &sha).unwrap();
    fs::remove_file(alias).unwrap();
    let file = root.path().join("payload.txt");
    fs::set_permissions(file, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(verify_source(root.path(), &sha).is_err());
}
