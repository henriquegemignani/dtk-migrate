//! `dtk-migrate configure-hook` — the command Ninja re-enters when it
//! regenerates its own build graph.
//!
//! A migration patches two rules in the generated `build.ninja`. Ninja
//! regenerates that file whenever `configure.py` or its inputs change, which
//! would quietly undo the patch part-way through a build — and the first thing
//! the unpatched splitter does is rewrite the project's `splits.txt`, which is
//! exactly what a reversible trial must not do.
//!
//! So the patched configure rule runs this instead: it runs the project's own
//! configure exactly as it would have been run, then applies the same patch to
//! whatever it produced.

use std::{ffi::OsString, path::PathBuf, process::Command};

use anyhow::{Result, bail};
use clap::Args as ClapArgs;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Ninja job bound to write into the regenerated split rule.
    #[arg(long, default_value_t = 4)]
    pub jobs: usize,
    /// The project's own configure command, after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 1..)]
    pub command: Vec<OsString>,
}

pub fn run(args: Args) -> Result<()> {
    let Some((program, rest)) = args.command.split_first() else {
        bail!("configure-hook needs the configure command after `--`");
    };
    let status = Command::new(program).args(rest).status()?;
    if !status.success() {
        bail!("configure.py failed with {status}");
    }
    // Ninja runs a generator rule in the project root, which is where the file
    // it just regenerated lives.
    let root = std::env::current_dir()?;
    let hook = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("dtk-migrate"));
    crate::build::configure::patch_in_place(&root, args.jobs, &hook.display().to_string())
}
