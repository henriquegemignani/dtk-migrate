//! One place that knows how to build a version of the project and say what it
//! measured.
//!
//! Every stage reaches the same conclusion the same way: write a candidate into
//! a private copy of the project, build it here, and read the report. A build
//! that does not reproduce retail bytes is not a result about the candidate — it
//! is a broken workspace — so that check lives here rather than in each stage.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use sha1::{Digest, Sha1};

use crate::{
    build::{
        awake_time::AwakeInstant,
        configure,
        process::{Cancel, CommandError, Spec, run},
    },
    project::report::Report,
};

/// A candidate was built, but what came out cannot be trusted as evidence.
///
/// Distinct from a build failure: the commands succeeded and still produced
/// something inconsistent, which is a stronger signal than a compiler error.
#[derive(Debug)]
pub struct ValidationError(pub String);

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

impl std::error::Error for ValidationError {}

/// The binaries a build needs, and where its prebuilt tools live.
#[derive(Debug, Clone)]
pub struct Toolchain {
    pub dtk: PathBuf,
    pub ninja: PathBuf,
    pub python: PathBuf,
    /// This binary, which the patched configure rule re-enters.
    pub hook: PathBuf,
    /// Where `build/compilers`, `build/tools` and `build/binutils` are found.
    ///
    /// A worker's private copy of the project does not contain the downloaded
    /// compilers; the owner's shared directory keeps them out of each worker's
    /// Ninja graph, where they would be download targets rather than inputs.
    pub toolchain_root: Option<PathBuf>,
}

/// Everything one build needs to know.
#[derive(Debug, Clone)]
pub struct BuildContext {
    /// The project copy to build. Never the user's checkout during a trial.
    pub root: PathBuf,
    pub source: String,
    pub target: String,
    /// Names requested by a focused run; empty means all candidates.
    pub only: Vec<String>,
    pub tools: Toolchain,
    /// Where the command log and this stage's evidence are written.
    pub output: PathBuf,
    pub build_jobs: usize,
    /// Bound on a *candidate* build, applied by [`trial_build`](Self::trial_build).
    /// A cold baseline build is deliberately unbounded.
    pub build_timeout: Option<Duration>,
    pub cancel: Option<Cancel>,
}

impl BuildContext {
    /// Runs one command in the project copy, logging it.
    pub fn run(
        &self,
        program: &Path,
        args: &[String],
        capture: bool,
        timeout: Option<Duration>,
    ) -> Result<String, CommandError> {
        std::fs::create_dir_all(&self.output)?;
        run(&Spec {
            program,
            args: args.to_vec(),
            cwd: &self.root,
            env: self.env(),
            log: &self.output.join("build.log"),
            capture,
            timeout,
            cancel: self.cancel.clone(),
        })
    }

    /// Bounds the native thread pools inside the tools we invoke.
    ///
    /// Ninja's own `-j` only limits the processes it starts. dtk and the
    /// compilers each have their own pools, and without this a three-worker run
    /// oversubscribes the machine by a factor of its core count.
    fn env(&self) -> Vec<(String, String)> {
        let jobs = self.build_jobs.to_string();
        let mut env: Vec<(String, String)> =
            ["OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "RAYON_NUM_THREADS"]
                .iter()
                .map(|key| ((*key).to_string(), jobs.clone()))
                .collect();
        env.push(("DTK_MIGRATE_WORKSPACE_ROOT".to_string(), self.root.display().to_string()));
        env
    }

    /// Runs `configure.py`, then patches the build graph it generated.
    pub fn configure(&self) -> Result<()> {
        let mut args: Vec<String> = vec![
            "configure.py".into(),
            "configure".into(),
            "-v".into(),
            self.target.clone(),
            "--dtk".into(),
            self.tools.dtk.display().to_string(),
            "--ninja".into(),
            self.tools.ninja.display().to_string(),
        ];
        // Existing toolchains are inputs, not things for each worker's Ninja to
        // download again.
        for (flag, path) in self.toolchain_paths() {
            if path.exists() || (flag == "--compilers" && self.tools.toolchain_root.is_some()) {
                args.push(flag.to_string());
                args.push(path.display().to_string());
            }
        }
        self.run(&self.tools.python.clone(), &args, false, None)
            .map_err(|e| anyhow::anyhow!(e))
            .context("configure.py failed")?;
        configure::patch_in_place(
            &self.root,
            self.build_jobs,
            &self.tools.hook.display().to_string(),
        )
    }

    /// Regenerates the ordinary project build graph after migration trials.
    ///
    /// Trial graphs deliberately point their configure rule at the frozen
    /// migration binary, and their split rule uses trial-only flags. Those
    /// generated files are outside the workspace snapshot, so publishing the
    /// proven source inputs does not replace them. Regenerate through the
    /// project's normal defaults before returning the checkout to its owner;
    /// otherwise a later plain `ninja` can re-enter a completed run's hook.
    pub fn restore_generated_graph(&self) -> Result<()> {
        let args =
            vec!["configure.py".into(), "configure".into(), "-v".into(), self.target.clone()];
        self.run(&self.tools.python.clone(), &args, false, None)
            .map_err(|e| anyhow::anyhow!(e))
            .context("Failed to restore the project's ordinary build graph")?;
        Ok(())
    }

    fn toolchain_paths(&self) -> Vec<(&'static str, PathBuf)> {
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let tools = self.tools.toolchain_root.clone().unwrap_or_else(|| self.root.clone());
        vec![
            ("--compilers", tools.join("build/compilers")),
            ("--objdiff", tools.join(format!("build/tools/objdiff-cli{suffix}"))),
            ("--sjiswrap", tools.join("build/tools/sjiswrap.exe")),
            ("--binutils", tools.join("build/binutils")),
        ]
    }

    /// Configures, links and checks retail bytes before generating the report.
    ///
    /// Link/hash failures are common candidate outcomes and need no objdiff
    /// report. Asking Ninja for both targets together lets it run the report
    /// first, which can spend the whole trial timeout measuring a state the
    /// linker would reject in seconds. The two invocations share one timeout
    /// budget so this ordering cannot make a bounded trial run twice as long.
    pub fn build(&self, timeout: Option<Duration>) -> Result<Report> {
        self.configure()?;
        let started = AwakeInstant::now();
        let link_args: Vec<String> =
            vec!["-j".into(), self.build_jobs.to_string(), format!("build/{}/ok", self.target)];
        self.run(&self.tools.ninja.clone(), &link_args, false, timeout)
            .map_err(|e| anyhow::anyhow!(e))
            .context("ninja link/hash check failed")?;

        // The `ok` target is a checksum comparison the project performs itself.
        // Reading the bytes as well costs nothing and catches a stale or
        // misconfigured checksum target, which would otherwise pass a candidate
        // whose output is not retail at all.
        let retail = self.root.join("orig").join(&self.target).join("sys/main.dol");
        let built = self.built_dol();
        if std::fs::read(&retail).ok() != std::fs::read(&built).ok() {
            bail!(ValidationError(
                "Retail DOL bytes differ despite passing the checksum target".into()
            ));
        }

        let report_args: Vec<String> = vec![
            "-j".into(),
            self.build_jobs.to_string(),
            format!("build/{}/report.json", self.target),
        ];
        self.run(&self.tools.ninja.clone(), &report_args, false, remaining(timeout, started)?)
            .map_err(|e| anyhow::anyhow!(e))
            .context("ninja report generation failed")?;
        Report::read(&self.root.join("build").join(&self.target).join("report.json"))
    }

    /// Builds a candidate under the run's bounded trial timeout.
    pub fn trial_build(&self) -> Result<Report> { self.build(self.build_timeout) }

    pub fn built_dol(&self) -> PathBuf {
        self.root.join("build").join(&self.target).join("main.dol")
    }

    pub fn dol_sha1(&self) -> Result<String> {
        let bytes = std::fs::read(self.built_dol())?;
        Ok(format!("{:x}", Sha1::digest(&bytes)))
    }
}

fn remaining(limit: Option<Duration>, started: AwakeInstant) -> Result<Option<Duration>> {
    let Some(limit) = limit else { return Ok(None) };
    let elapsed = started.elapsed();
    if let Some(remaining) = limit.checked_sub(elapsed)
        && !remaining.is_zero()
    {
        return Ok(Some(remaining));
    }
    Err(anyhow::Error::new(CommandError::TimedOut { after: elapsed, evidence: None })
        .context("candidate timeout expired before report generation"))
}

/// Whether an error is a candidate's fault rather than the run's.
///
/// A failed or timed-out build and a validation failure all say something about
/// the candidate, so a stage bisects and carries on. A cancellation says nothing
/// about it, and neither does a missing file or an unparseable report — those
/// stop the run.
pub fn is_trial_failure(error: &anyhow::Error) -> bool {
    if error.downcast_ref::<ValidationError>().is_some() {
        return true;
    }
    matches!(
        error.downcast_ref::<CommandError>(),
        Some(CommandError::Failed { .. } | CommandError::TimedOut { .. })
    ) || error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<CommandError>(),
            Some(CommandError::Failed { .. } | CommandError::TimedOut { .. })
        ) || cause.downcast_ref::<ValidationError>().is_some()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_build_failure_is_the_candidates_fault() {
        let error = anyhow::Error::new(CommandError::Failed { status: Some(1), evidence: None });
        assert!(is_trial_failure(&error));
        let wrapped = error_with_context(CommandError::Failed { status: Some(1), evidence: None });
        assert!(is_trial_failure(&wrapped));
    }

    #[test]
    fn a_timeout_is_the_candidates_fault() {
        let error = error_with_context(CommandError::TimedOut {
            after: Duration::from_secs(1),
            evidence: None,
        });
        assert!(is_trial_failure(&error));
    }

    #[test]
    fn a_validation_failure_is_the_candidates_fault() {
        let error = anyhow::Error::new(ValidationError("retail bytes differ".into()))
            .context("while trying a candidate");
        assert!(is_trial_failure(&error));
    }

    #[test]
    fn a_cancellation_stops_the_run_instead() {
        let error = error_with_context(CommandError::Cancelled);
        assert!(!is_trial_failure(&error));
    }

    #[test]
    fn an_unreadable_report_stops_the_run_instead() {
        let error = anyhow::anyhow!("Failed to parse report.json");
        assert!(!is_trial_failure(&error));
    }

    #[test]
    fn two_build_phases_share_one_timeout_budget() {
        let started = AwakeInstant::now();
        let left = remaining(Some(Duration::from_secs(1)), started).unwrap().unwrap();
        assert!(left <= Duration::from_secs(1));
        assert!(is_trial_failure(&remaining(Some(Duration::ZERO), started).unwrap_err()));
        assert_eq!(remaining(None, started).unwrap(), None);
    }

    fn error_with_context(error: CommandError) -> anyhow::Error {
        anyhow::Error::new(error).context("ninja failed")
    }
}
