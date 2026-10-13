use std::{
    fs,
    io::{self, Write},
    process::{Command, Stdio},
    time::Duration,
};
// Deliberately orphan a process to exercise the launcher's descendant cleanup.
#[allow(clippy::zombie_processes)]
fn main() {
    let mode = std::env::args().nth(1).unwrap();
    match mode.as_str() {
        "output" => {
            println!("private actual child output");
            eprintln!("private actual child error");
        }
        "fail" => {
            println!("private actual child output");
            std::process::exit(9);
        }
        "flood" => {
            let block = [b'x'; 8192];
            loop {
                io::stdout().write_all(&block).unwrap();
            }
        }
        "descendant" => {
            std::thread::sleep(Duration::from_secs(1));
            fs::write("escaped", "must not survive").unwrap();
        }
        "orphan-pipes" => {
            let _descendant = Command::new(std::env::current_exe().unwrap())
                .arg("descendant")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();
        }
        "orphan" | "timeout" => {
            let mut descendant = Command::new(std::env::current_exe().unwrap())
                .arg("descendant")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            if mode == "timeout" {
                let _ = descendant.wait();
                std::thread::sleep(Duration::from_secs(30));
            }
        }
        "signal-runner" => {
            omni_release_launcher::process::install_termination_handler().unwrap();
            let base = std::env::args().nth(2).unwrap();
            let temp = tempfile::tempdir_in(&base).unwrap();
            fs::write(
                std::path::Path::new(&base).join("private-path"),
                temp.path().to_str().unwrap(),
            )
            .unwrap();
            let result = omni_release_launcher::process::run(
                &std::env::current_exe().unwrap(),
                &["timeout".into()],
                temp.path(),
                &omni_release_launcher::Environment::new(),
                Duration::from_secs(30),
                None,
            );
            drop(temp);
            assert!(result.is_err());
            std::process::exit(1);
        }
        _ => std::process::exit(10),
    }
}
