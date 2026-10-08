use std::process::exit;

use clap::{Parser, Subcommand};
use dtk_migrate::cli;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "dtk-migrate",
    version,
    about = "Cross-version split discovery and source migration for decomp-toolkit projects"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Minimum logging level: error, warn, info, debug, trace. Default: info.
    #[arg(short = 'L', long, global = true)]
    log_level: Option<LevelFilter>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the migration pipeline and publish what it proves.
    Run(cli::run::Args),
    /// Match functions between two versions of the same executable.
    Match(cli::match_cmd::Args),
    /// Name target symbols by comparing a unit's two compiled objects.
    Derive(cli::derive::Args),
    /// Explore unresolved names with objdiff, caller evidence, and a per-unit inventory.
    Explore(cli::explore::Args),
    /// Report what the existing splits already get wrong.
    Audit(cli::audit::Args),
    /// Score the coverage policy against a version that already has the answers.
    Calibrate(cli::calibrate::Args),
    /// Score a finished migration against a later revision of the same project.
    Benchmark(cli::benchmark::Args),
    /// Work with a version's symbols file.
    Symbols(cli::symbols::Args),
    /// Work with a version's splits file.
    Splits(cli::splits::Args),
    /// Internal: re-apply the build graph patch when Ninja regenerates it.
    #[command(hide = true)]
    ConfigureHook(cli::configure_hook::Args),
}

fn main() {
    let args = Cli::parse();

    let format = tracing_subscriber::fmt::format().with_target(false).without_time();
    // Logs go to stderr so stdout stays free for anything a command prints as
    // data, and so a caller can separate the two.
    let builder = tracing_subscriber::fmt().event_format(format).with_writer(std::io::stderr);
    if let Some(level) = args.log_level {
        builder.with_max_level(level).init();
    } else {
        builder
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .init();
    }

    let result = match args.command {
        Command::Run(c_args) => cli::run::run(c_args),
        Command::Match(c_args) => cli::match_cmd::run(c_args),
        Command::Derive(c_args) => cli::derive::run(c_args),
        Command::Explore(c_args) => cli::explore::run(c_args),
        Command::Audit(c_args) => cli::audit::run(c_args),
        Command::Calibrate(c_args) => cli::calibrate::run(c_args),
        Command::Benchmark(c_args) => cli::benchmark::run(c_args),
        Command::Symbols(c_args) => cli::symbols::run(c_args),
        Command::Splits(c_args) => cli::splits::run(c_args),
        Command::ConfigureHook(c_args) => cli::configure_hook::run(c_args),
    };
    if let Err(e) = result {
        eprintln!("Failed: {e:?}");
        exit(1);
    }
}
