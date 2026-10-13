//! Real subprocess failures must expose only bounded, non-secret outcome metadata.
use omni_release_launcher::process;
use std::{fs, process::Command, time::Duration};

fn capture(mode: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_summary_probe", "--nocapture"])
        .env("OMNI_TEST_SUMMARY_MODE", mode)
        .output()
        .unwrap()
}

#[test]
fn failed_process_reports_exit_status_without_echoing_child_output() {
    let output = capture("exit");
    assert!(output.status.success(), "local process fixture failed");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "Native subprocess failed: exit-code=101\nNative subprocess category: compiler\nNative compiler diagnostic: E0308\n"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE_SENTINEL"));
}

#[test]
fn successful_process_does_not_emit_failure_metadata() {
    let output = capture("success");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE_SENTINEL"));
}

#[cfg(unix)]
#[test]
fn signalled_process_reports_signal_not_an_invented_out_of_memory_cause() {
    let output = capture("signal");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!("Native subprocess failed: signal={}\n", libc::SIGTERM)
    );
}

#[test]
fn compiler_diagnostics_are_deduplicated_and_capped() {
    let output = capture("many-codes");
    assert!(output.status.success());
    let mut expected =
        "Native subprocess failed: exit-code=101\nNative subprocess category: compiler\n"
            .to_owned();
    for code in 0..8 {
        expected.push_str(&format!("Native compiler diagnostic: E{code:04}\n"));
    }
    assert_eq!(String::from_utf8(output.stderr).unwrap(), expected);
}

#[test]
fn failure_categories_never_echo_packages_paths_or_private_test_names() {
    let output = capture("categories");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "Native subprocess failed: exit-code=101\nNative subprocess category: build-script\nNative subprocess category: dependency-download\nNative subprocess category: storage-full\nNative subprocess category: subprocess-killed\nNative subprocess category: tests\n"
    );
}

#[test]
fn malformed_or_unknown_child_output_has_no_raw_fallback() {
    let output = capture("unknown");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "Native subprocess failed: exit-code=101\n"
    );
}

#[test]
fn process_summary_probe() {
    let Ok(mode) = std::env::var("OMNI_TEST_SUMMARY_MODE") else {
        return;
    };
    let temp = tempfile::tempdir().unwrap();
    let log_path = temp.path().join("private.log");
    let mut log = fs::File::create(&log_path).unwrap();
    let mut environment = omni_release_launcher::clean_environment(&std::env::vars().collect());
    environment.insert("OMNI_TEST_SUMMARY_CHILD_MODE".into(), mode.clone());
    let result = process::run(
        &std::env::current_exe().unwrap(),
        &[
            "--exact".into(),
            "process_summary_child".into(),
            "--nocapture".into(),
        ],
        temp.path(),
        &environment,
        Duration::from_secs(10),
        Some(&mut log),
    );
    assert_eq!(result.is_ok(), mode == "success");
    if mode != "signal" {
        assert!(
            fs::read(log_path)
                .unwrap()
                .windows(b"PRIVATE_SENTINEL".len())
                .any(|window| window == b"PRIVATE_SENTINEL")
        );
    }
}

#[test]
fn process_summary_child() {
    let Ok(mode) = std::env::var("OMNI_TEST_SUMMARY_CHILD_MODE") else {
        return;
    };
    if mode == "signal" {
        #[cfg(unix)]
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        panic!("signal fixture did not terminate");
    }
    if mode == "many-codes" {
        for code in 0..100 {
            eprintln!("error[E{code:04}]: PRIVATE_SENTINEL {code}");
            eprintln!("error[E{code:04}]: PRIVATE_SENTINEL repeated");
        }
        std::process::exit(101);
    }
    if mode == "categories" {
        eprintln!("error: failed to run custom build command for `PRIVATE_SENTINEL`");
        eprintln!("error: failed to download PRIVATE_SENTINEL");
        eprintln!("error: failed to get PRIVATE_SENTINEL");
        eprintln!("PRIVATE_SENTINEL: No space left on device (os error 28)");
        eprintln!("PRIVATE_SENTINEL (signal: 9, SIGKILL: kill)");
        println!("test result: FAILED. PRIVATE_SENTINEL");
        eprintln!("error: test failed, PRIVATE_SENTINEL");
        std::process::exit(101);
    }
    if mode == "unknown" {
        use std::io::Write;
        eprintln!("error[E12345]: PRIVATE_SENTINEL invalid code");
        eprintln!("error[E12]: PRIVATE_SENTINEL invalid code");
        eprintln!("error[Echo]: PRIVATE_SENTINEL invalid code");
        eprintln!("error[E0001]PRIVATE_SENTINEL invalid delimiter");
        eprintln!("error[Eéé]: PRIVATE_SENTINEL invalid UTF-8 code shape");
        eprintln!("##[error]PRIVATE_SENTINEL workflow command");
        std::io::stderr()
            .write_all(b"\xff\xfe PRIVATE_SENTINEL\n")
            .unwrap();
        std::process::exit(101);
    }
    eprintln!("error[E0308]: PRIVATE_SENTINEL compiler text /private/source.rs");
    eprintln!("error[E0308]: PRIVATE_SENTINEL repeated code");
    eprintln!("error[E12345]: PRIVATE_SENTINEL malformed code");
    eprintln!("error[PRIVATE_SENTINEL]: must not be echoed");
    eprintln!("##[error]PRIVATE_SENTINEL workflow injection");
    println!("PRIVATE_SENTINEL stdout");
    if mode != "success" {
        std::process::exit(101);
    }
}
