//! `dtk-migrate run` — the whole pipeline, from proposals to a published
//! result.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;
use serde::Serialize;

use crate::{
    run::{
        CoordinatorUpgrade, Environment, FrozenTools, ORDER, RESUME_COMPATIBILITY, RepositoryState,
        RunDir, RunRecord, SCHEMA, StageResult, publish, run_stage, stage_for, write_json,
    },
    stages::{MutationScope, Prepared},
    workspace::{LOCK_NAME, ProjectLock, Snapshot},
};

/// Same-schema binaries released before `resume_compatibility` was recorded,
/// audited as producing artifacts this build interprets identically. Keep this
/// list exact: a blanket schema-9 exemption would mix older ownership policies.
const COMPATIBLE_LEGACY_COORDINATORS: [&str; 2] = [
    "c014d5828731dfdbc8477307832a2ed9e6763fc62e884c4f1b2ab994b75735e0",
    "c0deef83c7c621b5b519bbfd3a59929f30464947bd77bb7384b5bef409b8b476",
];

const MAX_BUILD_TIMEOUT_SECONDS: f64 = 60.0;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The dtk-template project to migrate.
    #[arg(long, default_value = ".")]
    pub project_root: PathBuf,
    /// The version whose progress is being carried over.
    #[arg(long)]
    pub source: Option<String>,
    /// The version being migrated to.
    #[arg(long)]
    pub target: Option<String>,
    /// Which stages to run, in the order derive, coverage, discover, verify.
    /// Accepts `all` or a comma-separated list.
    #[arg(long, default_value = "coverage,discover", value_delimiter = ',')]
    pub stages: Vec<String>,
    /// How many candidate batches to evaluate at once, each in its own copy of
    /// the project.
    #[arg(long, default_value_t = default_workers())]
    pub workers: usize,
    /// Ninja jobs inside each worker.
    #[arg(long, default_value_t = 4)]
    pub build_jobs: usize,
    /// Candidates per batch. Failures are bisected, so a larger batch costs
    /// less when it passes and more when it does not.
    #[arg(long, default_value_t = 40)]
    pub batch_size: usize,
    /// Evaluate at most this many candidates per stage.
    #[arg(long)]
    pub limit: Option<usize>,
    /// Evaluate only this unit. Repeat to name more than one.
    #[arg(long)]
    pub only: Vec<String>,
    /// Seconds a candidate build may take before its process tree is killed.
    /// The first, cold build of a workspace is deliberately not bounded.
    #[arg(long, default_value_t = MAX_BUILD_TIMEOUT_SECONDS)]
    pub build_timeout: f64,
    /// The decomp-toolkit binary. Defaults to the project's own.
    #[arg(long)]
    pub dtk: Option<PathBuf>,
    /// The Ninja binary. Defaults to the first on PATH, resolved through a
    /// package manager's launcher if it finds one.
    #[arg(long)]
    pub ninja: Option<PathBuf>,
    /// The interpreter that runs the project's `configure.py`.
    #[arg(long)]
    pub python: Option<PathBuf>,
    /// Continue the run with this id instead of starting a new one.
    #[arg(long, value_name = "RUN_ID")]
    pub resume: Option<String>,
    /// Resume using this compatible dtk-migrate build, recording the upgrade.
    /// Completed worker jobs retain their original measurement identity.
    #[arg(long, requires = "resume")]
    pub resume_with_current: bool,
}

fn default_workers() -> usize {
    let cores = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    (cores / 4).clamp(1, 6)
}

/// What the whole run concluded, written to `result.json`.
#[derive(Debug, Serialize)]
struct Summary {
    schema: u32,
    id: String,
    source: String,
    target: String,
    stages: BTreeMap<String, StageResult>,
    published_dol_sha1: String,
    matched_code: u64,
    total_code: u64,
    complete_code: u64,
}

pub fn run(args: Args) -> Result<()> {
    let root = std::path::absolute(&args.project_root)?;
    if !root.join("configure.py").is_file() {
        bail!("{} does not look like a dtk-template project", root.display());
    }
    // One migration per checkout: two at once share Ninja state and dtk caches
    // and produce a build nobody can reconstruct.
    let _lock = ProjectLock::acquire(&root)?;

    let (dir, mut record) = match &args.resume {
        Some(id) => resume(&root, id)?,
        None => start(&root, &args)?,
    };
    crate::run::check_environment(&record)?;
    let already_published = published(&dir)?;
    if args.resume_with_current {
        if already_published {
            bail!("Run {} is already published and does not need a coordinator upgrade", record.id);
        }
        upgrade_coordinator(&dir, &mut record, &std::env::current_exe()?)?;
    }
    // The frozen hook is also the coordinator that interprets evidence and
    // decides what to publish. A same-schema rebuild must not silently finish
    // an incomplete run under the old binary's recorded identity.
    if !already_published {
        require_frozen_coordinator(
            &record.environment.migrate_sha256,
            &record.tools.hook,
            &std::env::current_exe()?,
        )?;
    }

    match publish::recover(&root, &dir)? {
        Some(publish::Status::Published) => {
            if !dir.path.join("result.json").is_file() {
                bail!("Published run {} has no result.json", record.id);
            }
            tracing::info!(
                "Run {} was already published; evidence: {}",
                record.id,
                dir.path.display()
            );
            return Ok(());
        }
        Some(publish::Status::UserEditConflict) => bail!(
            "An interrupted publication could not be fully undone because the project was \
             edited since. Resolve those files by hand before resuming."
        ),
        _ => {}
    }

    let mut current = root.clone();
    let mut reserved: BTreeSet<MutationScope> = BTreeSet::new();
    let mut results: BTreeMap<String, (StageResult, Prepared)> = BTreeMap::new();
    let mut resolved: BTreeSet<String> = BTreeSet::new();
    for stage in &record.stages {
        let (integrated, result) = run_stage(&dir, &record, stage, &current, &reserved, None)?;
        // Reserve in the mutation's namespace. A derived symbol name must not
        // exclude a later unit with the same spelling. Transaction neighbours
        // remain unit-scoped because their ownership changed too.
        reserved.extend(result.changed_scopes(stage_for(stage)?.as_ref())?);
        let prepared: crate::run::StoredPreparation =
            crate::run::read_json(&dir.stage(stage).join("prepared.json"))?;
        resolved.extend(prepared.only_resolved.iter().cloned());
        tracing::info!(
            "{stage}: accepted {}, deferred {}",
            result.accepted.len(),
            result.deferred.len()
        );
        results.insert(stage.clone(), (result, prepared.prepared));
        current = integrated;
    }

    crate::run::check_only_resolved(&record.only, &resolved)?;
    publish::publish(&root, &current, &dir, &record, &results, |report| {
        let summary = Summary {
            schema: SCHEMA,
            id: record.id.clone(),
            source: record.source.clone(),
            target: record.target.clone(),
            stages: results
                .iter()
                .map(|(name, (result, _))| (name.clone(), result.clone()))
                .collect(),
            published_dol_sha1: crate::run::context(
                &root,
                &record,
                dir.path.join("owner-validation"),
                None,
            )
            .dol_sha1()?,
            matched_code: report.measures.matched_code,
            total_code: report.measures.total_code,
            complete_code: report.measures.complete_code,
        };
        publish::write_json_atomic(&dir.path.join("result.json"), &summary)
    })?;
    tracing::info!("Published. Evidence: {}", dir.path.display());
    Ok(())
}

fn start(root: &Path, args: &Args) -> Result<(RunDir, RunRecord)> {
    let (Some(source), Some(target)) = (&args.source, &args.target) else {
        bail!("--source and --target are required for a new run");
    };
    if args.workers == 0 || args.build_jobs == 0 {
        bail!("--workers and --build-jobs must be positive");
    }
    validate_build_timeout(args.build_timeout)?;
    let stages = resolve_stages(&args.stages)?;
    // Capture the inputs before creating the run directory or freezing tools,
    // with Git state on both sides so a concurrent edit cannot be recorded as
    // belonging to a clean revision. The root lock is already held, so
    // repository_state excludes that one owned untracked path.
    let repository_before = repository_state(root)?;
    let owner = Snapshot::of(root)?;
    let repository = repository_state(root)?;
    if repository != repository_before {
        bail!("The project's Git state changed while its inputs were being captured")
    }

    let id = timestamp_id();
    let dir = RunDir { path: publish::run_directory(root, &id)? };
    if dir.path.exists() {
        bail!("Run {id} already exists");
    }
    std::fs::create_dir_all(&dir.path)?;

    // Freeze the tools, so a mid-run rebuild of dtk cannot change what a later
    // batch means.
    let tools_dir = dir.path.join("tools");
    std::fs::create_dir_all(&tools_dir)?;
    let dtk = freeze(&resolve_dtk(root, args.dtk.as_deref())?, &tools_dir)?;
    let ninja = freeze(&resolve_ninja(args.ninja.as_deref())?, &tools_dir)?;
    let hook = freeze(&std::env::current_exe()?, &tools_dir)?;
    let python = resolve_python(args.python.as_deref())?;

    let source_bytes: u64 = owner
        .manifest
        .keys()
        .filter_map(|name| std::fs::metadata(root.join(name)).ok())
        .map(|m| m.len())
        .sum();
    // Every worker plus the frozen baseline and the integration copy.
    crate::workspace::preflight_space(
        &dir.path,
        source_bytes,
        (args.workers as u64 + 2) * stages.len() as u64,
    )?;

    let tools = FrozenTools {
        dtk,
        ninja,
        python,
        hook,
        // The downloaded compilers stay where they are: copying them into every
        // worker would multiply gigabytes, and they are inputs, not outputs.
        toolchain_root: root.to_path_buf(),
    };
    let record = RunRecord {
        schema: SCHEMA,
        resume_compatibility: RESUME_COMPATIBILITY,
        id,
        root: root.to_path_buf(),
        source: source.clone(),
        target: target.clone(),
        stages,
        workers: args.workers,
        build_jobs: args.build_jobs,
        batch_size: args.batch_size,
        batching_version: crate::run::BATCHING_VERSION,
        limit: args.limit,
        only: args.only.clone(),
        build_timeout_seconds: Some(args.build_timeout),
        environment: Environment::of(&tools)?,
        artifact_environment: None,
        coordinator_upgrades: Vec::new(),
        repository,
        tools,
        owner,
    };
    write_json(&dir.path.join("run.json"), &record)?;
    tracing::info!("Run {}: {}", record.id, dir.path.display());
    Ok((dir, record))
}

fn validate_build_timeout(seconds: f64) -> Result<()> {
    if !seconds.is_finite() || seconds <= 0.0 || seconds > MAX_BUILD_TIMEOUT_SECONDS {
        bail!(
            "--build-timeout must be greater than zero and at most {MAX_BUILD_TIMEOUT_SECONDS} seconds"
        );
    }
    Ok(())
}

/// Rebinds an incomplete run to this executable without changing the identity
/// used by already completed worker jobs. The compatibility level is the
/// promise that their stored candidates and outcomes retain the same meaning.
fn upgrade_coordinator(dir: &RunDir, record: &mut RunRecord, executable: &Path) -> Result<()> {
    if effective_resume_compatibility(record) != RESUME_COMPATIBILITY {
        bail!(
            "Run {} has coordinator compatibility {}, but this build requires {}; start a fresh run",
            record.id,
            record.resume_compatibility,
            RESUME_COMPATIBILITY
        );
    }
    let digest = crate::workspace::hash_file(executable)?;
    if digest == record.environment.migrate_sha256 {
        tracing::info!("Run {} already uses this dtk-migrate executable", record.id);
        return Ok(());
    }

    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let frozen =
        dir.path.join("tools").join(format!("dtk-migrate-coordinator-{}{suffix}", &digest[..16]));
    if frozen.exists() {
        if crate::workspace::hash_file(&frozen)? != digest {
            bail!("Coordinator upgrade path contains different bytes: {}", frozen.display());
        }
    } else {
        std::fs::copy(executable, &frozen)
            .with_context(|| format!("Failed to freeze {}", executable.display()))?;
        if crate::workspace::hash_file(&frozen)? != digest {
            bail!("Frozen coordinator does not match {}", executable.display());
        }
    }

    let previous = record.environment.migrate_sha256.clone();
    if record.artifact_environment.is_none() {
        record.artifact_environment = Some(record.environment.clone());
    }
    record.resume_compatibility = RESUME_COMPATIBILITY;
    record.tools.hook = frozen.clone();
    // The old environment was checked immediately before this call. Change
    // only the executable identity; a concurrent PATH, evidence or tool change
    // must still disagree with the recorded environment on the next check.
    record.environment.migrate_sha256 = digest.clone();
    record.coordinator_upgrades.push(CoordinatorUpgrade {
        from_sha256: previous,
        to_sha256: digest,
        frozen_executable: frozen.clone(),
    });
    publish::write_json_atomic(&dir.path.join("run.json"), record)?;
    tracing::info!("Run {} upgraded to compatible coordinator {}", record.id, frozen.display());
    Ok(())
}

fn effective_resume_compatibility(record: &RunRecord) -> u32 {
    if record.resume_compatibility == 0
        && COMPATIBLE_LEGACY_COORDINATORS.contains(&record.environment.migrate_sha256.as_str())
    {
        RESUME_COMPATIBILITY
    } else {
        record.resume_compatibility
    }
}

fn repository_state(root: &Path) -> Result<Option<RepositoryState>> {
    let output =
        std::process::Command::new("git").arg("-C").arg(root).args(["rev-parse", "HEAD"]).output();
    let Ok(output) = output else { return Ok(None) };
    if !output.status.success() {
        return Ok(None);
    }
    let head = String::from_utf8(output.stdout)?.trim().to_string();
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=normal"])
        .output()
        .context("Failed to inspect the project's Git state")?;
    if !status.status.success() {
        bail!("git status failed in {}", root.display())
    }
    // The caller already owns this lock, and Prime intentionally does not
    // ignore it. It is the only worktree change the tool itself made before
    // recording provenance, so exclude exactly its untracked porcelain entry.
    let owned_lock = format!("?? {LOCK_NAME}\0");
    let clean = status.stdout.is_empty() || status.stdout == owned_lock.as_bytes();
    Ok(Some(RepositoryState { head, clean }))
}

fn resume(root: &Path, id: &str) -> Result<(RunDir, RunRecord)> {
    let dir = RunDir { path: publish::run_directory(root, id)? };
    let record: RunRecord = crate::run::read_json(&dir.path.join("run.json"))
        .with_context(|| format!("No run {id} under {}", publish::runs_root(root).display()))?;
    if record.schema != SCHEMA {
        bail!(
            "Run {id} uses schema {}, but this build requires schema {SCHEMA}; start a new run",
            record.schema
        );
    }
    Ok((dir, record))
}

fn published(dir: &RunDir) -> Result<bool> {
    let path = dir.path.join("publication.json");
    if !path.exists() {
        return Ok(false);
    }
    let journal: publish::Journal = crate::run::read_json(&path)?;
    Ok(journal.status == publish::Status::Published)
}

fn require_frozen_coordinator(expected: &str, frozen: &Path, executable: &Path) -> Result<()> {
    if crate::workspace::hash_file(executable)? != expected {
        bail!(
            "The current dtk-migrate executable differs from the one that started this run; \
             resume with the frozen executable at {}, pass --resume-with-current for an explicit \
             compatible upgrade, or start a fresh run",
            frozen.display()
        );
    }
    Ok(())
}

/// Expands `all` and puts the requested stages into the only order they may run
/// in.
fn resolve_stages(requested: &[String]) -> Result<Vec<String>> {
    let wanted: BTreeSet<&str> = if requested.iter().any(|s| s == "all") {
        ORDER.into_iter().collect()
    } else {
        requested.iter().map(String::as_str).collect()
    };
    for name in &wanted {
        if !ORDER.contains(name) {
            bail!("Unknown stage '{name}'; choose from {}", ORDER.join(", "));
        }
    }
    if wanted.is_empty() {
        bail!("No stages selected");
    }
    Ok(ORDER.iter().filter(|name| wanted.contains(*name)).map(|s| (*s).to_string()).collect())
}

fn freeze(binary: &Path, into: &Path) -> Result<PathBuf> {
    let name = binary.file_name().context("Tool path has no file name")?;
    let frozen = into.join(name);
    std::fs::copy(binary, &frozen)
        .with_context(|| format!("Failed to copy {}", binary.display()))?;
    Ok(frozen)
}

fn resolve_dtk(root: &Path, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return std::path::absolute(path).map_err(Into::into);
    }
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let default = root.join(format!("build/tools/dtk{suffix}"));
    if default.is_file() {
        return Ok(default);
    }
    bail!(
        "No decomp-toolkit binary found at {}; build the project once, or pass --dtk",
        default.display()
    )
}

/// Finds Ninja, seeing through a package manager's launcher.
///
/// Chocolatey puts a small shim on `PATH` that locates the real binary relative
/// to its own position. A run freezes its tools so a mid-run upgrade cannot
/// change what a later batch means, and freezing a shim freezes nothing: the
/// copy cannot find what it points at, and the failure surfaces as an
/// unexplained exit status from a build. The shim is resolved whether or not
/// the path was given explicitly, since someone passing `--ninja $(which
/// ninja)` should not get a different, broken answer.
fn resolve_ninja(explicit: Option<&Path>) -> Result<PathBuf> {
    let found = match explicit {
        Some(path) => std::path::absolute(path)?,
        None => which("ninja").context("Ninja not found; pass --ninja with its path")?,
    };
    let real =
        found.parent().and_then(Path::parent).map(|base| base.join("lib/ninja/tools/ninja.exe"));
    if found.parent().and_then(|p| p.file_name()).is_some_and(|n| n.eq_ignore_ascii_case("bin"))
        && let Some(real) = real
        && real.is_file()
    {
        return Ok(real);
    }
    if !found.is_file() {
        bail!("No Ninja binary at {}", found.display());
    }
    Ok(found)
}

fn resolve_python(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return std::path::absolute(path).map_err(Into::into);
    }
    which("python")
        .or_else(|| which("python3"))
        .context("Python not found; pass --python with its path")
}

fn which(program: &str) -> Option<PathBuf> {
    let suffixes: &[&str] = if cfg!(windows) { &[".exe", ""] } else { &[""] };
    let paths = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&paths) {
        for suffix in suffixes {
            let candidate = directory.join(format!("{program}{suffix}"));
            if candidate.is_file() {
                return std::path::absolute(candidate).ok();
            }
        }
    }
    None
}

fn timestamp_id() -> String {
    // Seconds since the epoch, formatted as a sortable stamp. A run id only has
    // to be unique and orderable, which does not justify a date library.
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let days = seconds / 86_400;
    let rest = seconds % 86_400;
    format!("{days:05}-{:02}{:02}{:02}", rest / 3600, (rest % 3600) / 60, rest % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upgrade_record(directory: &Path, original: &Path) -> RunRecord {
        let tools_dir = directory.join("tools");
        std::fs::create_dir_all(&tools_dir).unwrap();
        let dtk = tools_dir.join("dtk");
        let ninja = tools_dir.join("ninja");
        let hook = tools_dir.join("dtk-migrate");
        std::fs::write(&dtk, b"dtk").unwrap();
        std::fs::write(&ninja, b"ninja").unwrap();
        std::fs::copy(original, &hook).unwrap();
        let tools = FrozenTools {
            dtk,
            ninja,
            python: PathBuf::from("python"),
            hook,
            toolchain_root: directory.to_path_buf(),
        };
        RunRecord {
            schema: SCHEMA,
            resume_compatibility: RESUME_COMPATIBILITY,
            id: "run".into(),
            root: directory.to_path_buf(),
            source: "NTSC".into(),
            target: "PAL".into(),
            stages: vec!["verify".into()],
            workers: 1,
            build_jobs: 1,
            batch_size: 1,
            batching_version: crate::run::BATCHING_VERSION,
            limit: None,
            only: Vec::new(),
            build_timeout_seconds: Some(120.0),
            environment: Environment::of(&tools).unwrap(),
            artifact_environment: None,
            coordinator_upgrades: Vec::new(),
            tools,
            repository: None,
            owner: Snapshot { manifest: Default::default(), mappings: serde_json::Value::Null },
        }
    }

    #[test]
    fn changing_shared_compilers_invalidates_the_run_environment() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        std::fs::write(&original, "coordinator").unwrap();
        let compilers = directory.path().join("build/compilers");
        std::fs::create_dir_all(&compilers).unwrap();
        let compiler = compilers.join("compiler.exe");
        std::fs::write(&compiler, "before").unwrap();
        let record = upgrade_record(directory.path(), &original);
        crate::run::check_environment(&record).unwrap();
        std::fs::write(&compiler, "after").unwrap();
        assert!(crate::run::check_environment(&record).is_err());
        assert_ne!(
            Environment::of(&record.tools).unwrap().compilers_sha256,
            record.environment.compilers_sha256
        );
    }

    #[test]
    fn stages_run_in_the_fixed_order_whatever_order_they_are_asked_for() {
        let asked = ["verify".to_string(), "derive".to_string(), "discover".to_string()];
        assert_eq!(resolve_stages(&asked).unwrap(), ["derive", "discover", "verify"]);
    }

    #[test]
    fn all_means_every_stage() {
        assert_eq!(resolve_stages(&["all".to_string()]).unwrap(), ORDER);
    }

    #[test]
    fn a_stage_asked_for_twice_runs_once() {
        let asked = ["verify".to_string(), "verify".to_string()];
        assert_eq!(resolve_stages(&asked).unwrap(), ["verify"]);
    }

    #[test]
    fn an_unknown_stage_names_the_real_ones() {
        let error = resolve_stages(&["polish".to_string()]).unwrap_err().to_string();
        assert!(error.contains("derive"), "{error}");
    }

    #[test]
    fn no_stages_is_an_error() {
        assert!(resolve_stages(&[]).is_err());
    }

    #[test]
    fn new_runs_bound_candidate_builds_to_one_minute() {
        assert!(validate_build_timeout(60.0).is_ok());
        for seconds in [0.0, -1.0, 60.1, 120.0, f64::NAN, f64::INFINITY] {
            assert!(validate_build_timeout(seconds).is_err(), "{seconds}");
        }
    }

    #[test]
    fn a_run_id_is_sortable() {
        let id = timestamp_id();
        assert!(id.len() >= 12, "{id}");
        assert!(id.chars().all(|c| c.is_ascii_digit() || c == '-'), "{id}");
    }

    #[test]
    fn a_legacy_run_keeps_the_batch_partition_it_started_with() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        std::fs::write(&original, b"coordinator").unwrap();
        let mut value = serde_json::to_value(upgrade_record(directory.path(), &original)).unwrap();
        value.as_object_mut().unwrap().remove("batching_version");
        let record: RunRecord = serde_json::from_value(value).unwrap();
        assert_eq!(record.batching_version, 1);
    }

    #[test]
    fn the_tools_own_lock_does_not_make_a_clean_repository_dirty() {
        let directory = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .arg("-C")
                .arg(directory.path())
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        };
        git(&["init", "--quiet"]);
        std::fs::write(directory.path().join("tracked"), "original").unwrap();
        git(&["add", "tracked"]);
        git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ]);

        std::fs::write(directory.path().join(LOCK_NAME), "owned").unwrap();
        assert!(repository_state(directory.path()).unwrap().unwrap().clean);

        std::fs::write(directory.path().join("untracked"), "user input").unwrap();
        assert!(!repository_state(directory.path()).unwrap().unwrap().clean);
    }

    #[test]
    fn an_incomplete_run_requires_the_original_coordinator_binary() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        let rebuilt = directory.path().join("rebuilt");
        std::fs::write(&original, b"same schema, original policy").unwrap();
        std::fs::write(&rebuilt, b"same schema, changed policy").unwrap();
        let digest = crate::workspace::hash_file(&original).unwrap();
        require_frozen_coordinator(&digest, &original, &original).unwrap();
        let error =
            require_frozen_coordinator(&digest, &original, &rebuilt).unwrap_err().to_string();
        assert!(error.contains("differs"), "{error}");
        assert!(error.contains(&original.display().to_string()), "{error}");
        assert!(error.contains("--resume-with-current"), "{error}");
    }

    #[test]
    fn a_compatible_upgrade_is_frozen_recorded_and_keeps_worker_identity() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        let rebuilt = directory.path().join("rebuilt");
        std::fs::write(&original, b"original coordinator").unwrap();
        std::fs::write(&rebuilt, b"compatible fixed coordinator").unwrap();
        let dir = RunDir { path: directory.path().join("run") };
        std::fs::create_dir_all(&dir.path).unwrap();
        let mut record = upgrade_record(&dir.path, &original);
        let worker_environment = record.artifact_environment().clone();

        upgrade_coordinator(&dir, &mut record, &rebuilt).unwrap();

        assert_eq!(record.artifact_environment(), &worker_environment);
        assert_eq!(record.coordinator_upgrades.len(), 1);
        let upgrade = &record.coordinator_upgrades[0];
        assert_eq!(upgrade.from_sha256, worker_environment.migrate_sha256);
        assert_eq!(upgrade.to_sha256, crate::workspace::hash_file(&rebuilt).unwrap());
        assert_eq!(record.tools.hook, upgrade.frozen_executable);
        assert!(record.tools.hook.is_file());
        crate::run::check_environment(&record).unwrap();
        require_frozen_coordinator(
            &record.environment.migrate_sha256,
            &record.tools.hook,
            &rebuilt,
        )
        .unwrap();
        assert!(
            require_frozen_coordinator(
                &record.environment.migrate_sha256,
                &record.tools.hook,
                &original,
            )
            .is_err()
        );

        let stored: RunRecord = crate::run::read_json(&dir.path.join("run.json")).unwrap();
        assert_eq!(stored.coordinator_upgrades, record.coordinator_upgrades);
        upgrade_coordinator(&dir, &mut record, &rebuilt).unwrap();
        assert_eq!(record.coordinator_upgrades.len(), 1, "the same upgrade is a no-op");
    }

    #[test]
    fn an_incompatible_coordinator_cannot_upgrade_a_run() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        let rebuilt = directory.path().join("rebuilt");
        std::fs::write(&original, b"original coordinator").unwrap();
        std::fs::write(&rebuilt, b"incompatible coordinator").unwrap();
        let dir = RunDir { path: directory.path().join("run") };
        std::fs::create_dir_all(&dir.path).unwrap();
        let mut record = upgrade_record(&dir.path, &original);
        record.resume_compatibility += 1;

        let error = upgrade_coordinator(&dir, &mut record, &rebuilt).unwrap_err().to_string();
        assert!(error.contains("compatibility"), "{error}");
        assert!(record.coordinator_upgrades.is_empty());
    }

    #[test]
    fn legacy_runs_need_an_exact_audited_predecessor_digest() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        std::fs::write(&original, b"original coordinator").unwrap();
        let dir = RunDir { path: directory.path().join("run") };
        std::fs::create_dir_all(&dir.path).unwrap();
        let record = upgrade_record(&dir.path, &original);
        let mut value = serde_json::to_value(record).unwrap();
        value.as_object_mut().unwrap().remove("resume_compatibility");
        value["environment"]["migrate_sha256"] = serde_json::Value::String("unknown".into());
        let unknown: RunRecord = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(unknown.resume_compatibility, 0);
        assert_eq!(effective_resume_compatibility(&unknown), 0);

        value["environment"]["migrate_sha256"] =
            serde_json::Value::String(COMPATIBLE_LEGACY_COORDINATORS[0].into());
        let audited: RunRecord = serde_json::from_value(value).unwrap();
        assert_eq!(effective_resume_compatibility(&audited), RESUME_COMPATIBILITY);
    }
}
