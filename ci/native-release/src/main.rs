fn main() {
    if omni_release_launcher::process::install_termination_handler().is_err() {
        eprintln!("Native termination cleanup unavailable");
        std::process::exit(1);
    }
    let command = std::env::args().nth(1).unwrap_or_default();
    if [
        "prepare-installed-control",
        "prepare-protected-source-pair",
        "cleanup-hosted-inputs",
    ]
    .contains(&command.as_str())
    {
        if std::env::args().len() != 2 {
            eprintln!("Unexpected hosted input arguments");
            std::process::exit(1);
        }
        let environment = std::env::vars().collect();
        let result = if command == "cleanup-hosted-inputs" {
            omni_release_launcher::hosted_inputs::cleanup(&environment)
        } else {
            omni_release_launcher::hosted_inputs::run(&command, &environment)
        };
        if let Err(error) = result {
            eprintln!("Native hosted input: {error}");
            std::process::exit(1);
        }
        return;
    }
    if ["source-ci", "discover-source-ci", "report-source-ci"].contains(&command.as_str()) {
        let args: Vec<String> = std::env::args().skip(2).collect();
        let environment = std::env::vars().collect();
        let result = match command.as_str() {
            "source-ci" if args.is_empty() => omni_release_launcher::source_ci::run(&environment),
            "discover-source-ci" => {
                omni_release_launcher::source_discovery::discover_cli(&args, &environment)
            }
            "report-source-ci" => {
                omni_release_launcher::source_report::report_cli(&args, &environment)
            }
            _ => Err("Unexpected source-CI execution arguments"),
        };
        if let Err(error) = result {
            eprintln!("Native source-CI: {error}");
            std::process::exit(1);
        }
        return;
    }
    if command == "check-integration-prerequisites" {
        if std::env::args().len() != 2 {
            eprintln!("Unexpected prerequisite-check arguments");
            std::process::exit(1);
        }
        if let Err(error) =
            omni_release_launcher::prerequisites::check_integration(&std::env::vars().collect())
        {
            eprintln!("Native release preflight: {error}");
            std::process::exit(1);
        }
        return;
    }
    if command == "audit-runners" {
        let args: Vec<String> = std::env::args().skip(2).collect();
        if let Err(error) = omni_release_launcher::runner_policy::cli(&args) {
            eprintln!("Native runner policy: {error}");
            std::process::exit(1);
        }
        return;
    }
    if command == "check-ci-request" {
        let args: Vec<String> = std::env::args().skip(2).collect();
        if let Err(error) = omni_release_launcher::ci_request::check_cli(&args) {
            eprintln!("Native source-CI check: {error}");
            std::process::exit(1);
        }
        return;
    }
    if command == "--help" {
        println!(
            "omni-release-launcher resolve|run|verify-build|agent-run|validate-request|approve-source|agent-source\nomni-release-launcher sign-public-candidates|prepare-publication|publish-candidates|verify-ios|windows-sdk|retain-artifacts\nomni-release-launcher verify-source --root PATH --sha SHA\nomni-release-launcher verify-agent-handoff --directory PATH --version VERSION --platform PLATFORM"
        );
        return;
    }
    if let Err(error) = omni_release_launcher::launch::run(&command) {
        eprintln!("Native release launcher: {error}");
        std::process::exit(1);
    }
}
