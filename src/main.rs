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
    /// Match functions between two versions of the same executable.
    Match(cli::match_cmd::Args),
    /// Work with a version's symbols file.
    Symbols(cli::symbols::Args),
    /// Work with a version's splits file.
    Splits(cli::splits::Args),
}

fn main() {
    let args = Cli::parse();

    let format = tracing_subscriber::fmt::format().with_target(false).without_time();
    let builder = tracing_subscriber::fmt().event_format(format);
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
        Command::Match(c_args) => cli::match_cmd::run(c_args),
        Command::Symbols(c_args) => cli::symbols::run(c_args),
        Command::Splits(c_args) => cli::splits::run(c_args),
    };
    if let Err(e) = result {
        eprintln!("Failed: {e:?}");
        exit(1);
    }
}
