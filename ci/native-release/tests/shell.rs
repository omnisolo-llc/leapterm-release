#![cfg(unix)]
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn script(path: &Path, content: &str) {
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn installed_pinned_contract_tools_do_not_require_a_toolchain_directory_write() {
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    script(
        &bin.join("rustup"),
        "#!/bin/sh\n[ \"$1\" = run ] || exit 93\n[ \"$2\" = 1.95.0 ] || exit 94\nexit 0\n",
    );
    script(
        &bin.join("cargo"),
        "#!/bin/sh\n[ \"$1\" = +1.95.0 ] || exit 94\nif [ \"$2\" = test ]; then echo 'test result: ok. 1 passed; 0 failed'; fi\nexit 0\n",
    );
    let output = Command::new("bash")
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("test-native-release.sh"),
        )
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        )
        .env("TMPDIR", temp.path())
        .env_remove("DIAGNOSTICS_PUBLIC_KEY")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("test result: ok."));
    assert_eq!(
        fs::read_dir(temp.path()).unwrap().count(),
        1,
        "Temporary logs/guards must be removed"
    );
}
