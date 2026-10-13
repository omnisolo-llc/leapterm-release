use omni_release_launcher::{Environment, process};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};
fn child() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_contract-child"))
}
#[test]
fn actual_child_output_and_failure_are_private_and_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("log");
    let mut log = fs::File::create(&path).unwrap();
    let env = Environment::new();
    let bytes = process::run(
        child(),
        &["output".into()],
        temp.path(),
        &env,
        Duration::from_secs(5),
        Some(&mut log),
    )
    .unwrap();
    assert_eq!(bytes, b"private actual child output\n");
    let error = process::run(
        child(),
        &["fail".into()],
        temp.path(),
        &env,
        Duration::from_secs(5),
        Some(&mut log),
    )
    .unwrap_err();
    assert!(!error.contains("private actual"));
    assert!(fs::read_to_string(path).unwrap().contains("private actual"));
    let start = Instant::now();
    assert!(
        process::run(
            child(),
            &["flood".into()],
            temp.path(),
            &env,
            Duration::from_secs(10),
            None
        )
        .is_err()
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "Overflow must stop a running child promptly"
    );
}
#[test]
fn exited_parent_cannot_leave_descendants_running_while_collecting_output() {
    let temp = tempfile::tempdir().unwrap();
    process::run(
        child(),
        &["orphan-pipes".into()],
        temp.path(),
        &Environment::new(),
        Duration::from_secs(5),
        None,
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        !temp.path().join("escaped").exists(),
        "output collection must not extend a descendant's authority after its parent exits"
    );
}

#[test]
fn timeout_and_success_stop_all_descendants_even_if_their_pipes_close() {
    for mode in ["orphan", "timeout"] {
        let temp = tempfile::tempdir().unwrap();
        let result = process::run(
            child(),
            &[mode.into()],
            temp.path(),
            &Environment::new(),
            Duration::from_millis(500),
            None,
        );
        let disposition = match &result {
            Ok(_) => "success",
            Err("Build command timed out") => "timeout",
            Err("Build output stream did not close") => "stream",
            Err("Required build tool could not start") => "start",
            Err("Process-tree cleanup unavailable") => "group",
            Err("Suspended process cannot resume") => "resume",
            Err("Build command failed; inspect private diagnostics") => "failed",
            Err(_) => "other",
        };
        println!("Native boundary result: {mode} {disposition}");
        assert_eq!(result.is_ok(), mode == "orphan");
        std::thread::sleep(Duration::from_millis(1200));
        println!(
            "Native boundary result: {mode} {}",
            if temp.path().join("escaped").exists() {
                "escaped"
            } else {
                "clean"
            }
        );
        assert!(
            !temp.path().join("escaped").exists(),
            "Descendant survived {mode}"
        );
    }
}
#[test]
#[cfg(unix)]
fn sigterm_unwinds_private_temp_and_kills_child_group() {
    use std::process::Command;
    let temp = tempfile::tempdir().unwrap();
    let mut runner = Command::new(child())
        .arg("signal-runner")
        .arg(temp.path())
        .spawn()
        .unwrap();
    let marker = temp.path().join("private-path");
    let start = Instant::now();
    while !marker.exists() {
        assert!(start.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(10));
    }
    let private = fs::read_to_string(marker).unwrap();
    unsafe {
        libc::kill(runner.id() as i32, libc::SIGTERM);
    }
    assert!(!runner.wait().unwrap().success());
    assert!(!Path::new(&private).exists());
}
