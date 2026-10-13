use omni_release_launcher::guards::{self, Frozen};
use std::{fs, path::Path};
#[test]
fn reviewed_tree_is_frozen_by_handle_restored_and_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("tools");
    fs::create_dir(&root).unwrap();
    let path = root.join("main.rs");
    fs::write(&path, "reviewed").unwrap();
    let original = fs::metadata(&path).unwrap().permissions();
    {
        let guard = Frozen::tree(&root, true).unwrap();
        guard.verify().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o222, 0);
            assert_eq!(
                fs::metadata(temp.path()).unwrap().permissions().mode() & 0o222,
                0
            );
        }
        #[cfg(windows)]
        assert!(fs::metadata(&path).unwrap().permissions().readonly());
    }
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().readonly(),
        original.readonly()
    );
    fs::write(&path, vec![0; 4 * 1024 * 1024 + 1]).unwrap();
    assert!(Frozen::tree(&root, false).is_err());
    fs::remove_file(&path).unwrap();
    for n in 0..1025 {
        fs::write(root.join(format!("file{n}")), b"").unwrap();
    }
    assert!(Frozen::tree(&root, false).is_err());
    let large = temp.path().join("large");
    fs::create_dir(&large).unwrap();
    for n in 0..5 {
        fs::write(large.join(format!("file{n}")), vec![0; 4 * 1024 * 1024]).unwrap();
    }
    assert!(Frozen::tree(&large, false).is_err());
    let directories = temp.path().join("directories");
    fs::create_dir(&directories).unwrap();
    for n in 0..2049 {
        fs::create_dir(directories.join(format!("dir{n}"))).unwrap();
    }
    assert!(Frozen::tree(&directories, false).is_err());
}
#[test]
#[cfg(unix)]
fn freezing_and_cleanup_never_chmod_outside_replacement_symlinks() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("tools");
    fs::create_dir(&root).unwrap();
    let outside = temp.path().join("outside");
    fs::write(&outside, "external").unwrap();
    let original = fs::metadata(&outside).unwrap().permissions().mode();
    let path = root.join("entry");
    symlink(&outside, &path).unwrap();
    assert!(Frozen::tree(&root, false).is_err());
    assert_eq!(
        fs::metadata(&outside).unwrap().permissions().mode(),
        original
    );
    fs::remove_file(&path).unwrap();
    fs::write(&path, "reviewed").unwrap();
    let guard = Frozen::tree(&root, false).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(&path).unwrap();
    symlink(&outside, &path).unwrap();
    assert!(guard.verify().is_err());
    drop(guard);
    assert_eq!(
        fs::metadata(&outside).unwrap().permissions().mode(),
        original
    );
}
#[test]
fn path_and_identity_guards_keep_windows_macos_and_hardlink_protections() {
    for path in [
        "../escape",
        "/absolute",
        "C:/drive",
        "x\\y",
        "a/.git/config",
        "a/CON.txt",
        "a/LPT1",
        "a/trailing.",
        "a/trailing ",
        "a\nsecret",
        "a//b",
        "",
    ] {
        assert!(!guards::safe_path(path), "{path}");
    }
    assert!(!guards::safe_path(&"a/".repeat(65)));
    assert!(!guards::safe_path(&"x".repeat(4097)));
    assert!(guards::safe_path("tools/release-cli/src/main.rs"));
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("regular");
    fs::write(&path, "original").unwrap();
    let file = guards::open_regular(&path, 16).unwrap();
    fs::rename(&path, temp.path().join("old")).unwrap();
    fs::write(&path, "original").unwrap();
    assert!(guards::unchanged(&file, &path).is_err());
    fs::hard_link(&path, temp.path().join("hardlink")).unwrap();
    assert!(guards::open_regular(&path, 16).is_err());
    assert!(guards::open_regular(Path::new("unavailable"), 16).is_err());
}
