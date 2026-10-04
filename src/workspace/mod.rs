//! Private copies of the game project, and proof that they are what we think.
//!
//! A trial has to compile, which means it has to write into a project. Doing
//! that in the user's checkout would make every run a race with whatever else
//! they are doing, so each worker gets its own copy and the coordinator keeps
//! the original untouched until there is something proven to publish.
//!
//! What gets copied is the *current* state of the checkout, not committed HEAD:
//! dirty files and untracked build inputs are exactly what someone wants
//! tested. Each included file is hashed on the way in, so a later run can say
//! whether the thing it measured is still the thing on disk.

use std::{
    collections::BTreeMap,
    fs::File,
    path::{Component, Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub const LOCK_NAME: &str = ".migration.lock";

/// Directories that are caches, history or agent scratch rather than build inputs.
const CACHE_NAMES: [&str; 10] = [
    ".git",
    ".agents",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
    ".venv",
    "venv",
    ".migration-runs",
];

/// Files at the project root that a build generates for itself.
const GENERATED_ROOT: [&str; 5] =
    ["objdiff.json", "build.ninja", "compile_commands.json", ".ninja_log", ".ninja_deps"];

/// Subdirectories of `build/` that hold tools rather than build output.
const TOOL_DIRS: [&str; 2] = ["tools", "binutils"];

/// Whether a path relative to the project root is a build input worth copying.
pub fn included(relative: &Path) -> bool {
    let parts: Vec<&str> = relative.iter().filter_map(|p| p.to_str()).collect();
    if parts.iter().any(|part| CACHE_NAMES.contains(part)) {
        return false;
    }
    if parts.len() == 1 && (GENERATED_ROOT.contains(&parts[0]) || parts[0] == LOCK_NAME) {
        return false;
    }
    if parts.first() == Some(&"build") {
        // Compilers are shared through configure.py --compilers, not copied.
        // Other downloaded tools remain workspace inputs.
        return parts.len() == 1 || TOOL_DIRS.contains(&parts[1]);
    }
    true
}

/// Every input file and its SHA-256, keyed by forward-slash relative path.
pub type Manifest = BTreeMap<String, String>;

/// Rejects a path that is a symlink or a Windows reparse point.
///
/// A snapshot that follows a link is not a copy of the project; it is a second
/// name for the original, and a trial writing through it would edit the user's
/// checkout.
fn reject_link(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Failed to stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("Snapshot paths cannot be symlinks or reparse points: {}", path.display());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("Snapshot paths cannot be symlinks or reparse points: {}", path.display());
        }
    }
    Ok(())
}

fn check_ancestors(path: &Path) -> Result<()> {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        prefix.push(component);
        if prefix.exists() {
            reject_link(&prefix)?;
        }
    }
    Ok(())
}

/// Resolves a manifest entry against a root, refusing anything that could
/// escape it.
///
/// Manifest paths come from a JSON file that a previous run wrote. Treating
/// them as trusted would let a corrupted or hand-edited run directory write
/// anywhere on disk.
pub fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    let candidate = Path::new(relative);
    let bad = relative.is_empty()
        || relative.contains('\\')
        || candidate.is_absolute()
        || candidate.components().any(|part| !matches!(part, Component::Normal(_)))
        || relative.split('/').any(|part| part.contains(':'));
    if bad {
        bail!("Unsafe manifest path: {relative}");
    }
    let mut current = root.to_path_buf();
    check_ancestors(&current)?;
    for part in relative.split('/') {
        current.push(part);
        if current.exists() {
            reject_link(&current)?;
        }
    }
    Ok(current)
}

pub fn hash_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// Hashes the project's actual inputs, including untracked files and populated
/// submodules.
pub fn snapshot_manifest(root: &Path) -> Result<Manifest> {
    let root = std::path::absolute(root)?;
    check_ancestors(&root)?;
    if !root.is_dir() {
        bail!("Snapshot root is not a directory: {}", root.display());
    }
    let mut manifest = Manifest::new();
    let walker = WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry.path() == root || entry.path().strip_prefix(&root).map(included).unwrap_or(false)
        });
    for entry in walker {
        let entry = entry?;
        let relative = entry.path().strip_prefix(&root)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        reject_link(entry.path())?;
        if entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            bail!("Snapshot input is not a regular file: {}", entry.path().display());
        }
        let key = relative
            .to_str()
            .with_context(|| format!("Path is not UTF-8: {}", relative.display()))?
            .replace('\\', "/");
        manifest.insert(key, hash_file(entry.path())?);
    }
    Ok(manifest)
}

/// Compilers are external shared inputs: hash them once for run provenance,
/// without putting them in any baseline, worker or integration copy.
pub fn compiler_manifest(root: &Path) -> Result<Manifest> {
    let path = root.join("build/compilers");
    if !path.exists() {
        return Ok(Manifest::new());
    }
    snapshot_manifest(&path)
}

/// A stable digest of anything serialisable, used to say "the same inputs".
pub fn fingerprint<T: Serialize>(value: &T) -> Result<String> {
    // Serde's JSON keeps map keys in the order the type produces, and every
    // map involved here is a BTreeMap, so the bytes are stable across runs.
    let bytes = serde_json::to_vec(value)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

/// Refuses to start when the copies plus headroom would not fit.
///
/// Each worker needs the project's inputs plus room for its own build output,
/// and running out of disk halfway through a link is a confusing failure to
/// debug from a compiler error message.
pub fn preflight_space(parent: &Path, source_bytes: u64, copies: u64) -> Result<()> {
    if copies == 0 {
        bail!("Copies must be positive");
    }
    let mut parent = std::path::absolute(parent)?;
    while !parent.exists() {
        match parent.parent() {
            Some(next) => parent = next.to_path_buf(),
            None => break,
        }
    }
    let required = copies * (source_bytes + (source_bytes / 4).max(256 * 1024 * 1024));
    let available = fs4::available_space(&parent)?;
    if available < required {
        bail!("Insufficient disk space: need {required} bytes, have {available}");
    }
    Ok(())
}

/// The longest path most Windows programs can open.
///
/// Long-path support has to be opted into per process, and the compilers a
/// decomp project uses are old enough that they have not.
const MAX_PATH: usize = 260;

/// Refuses to start when a workspace would put files past what the toolchain can
/// open.
///
/// A private workspace sits several directories below the project, which adds
/// fifty-odd characters to every path in it. CodeWarrior does not report a path
/// it cannot open: it reports the file that included it as a syntax error, on
/// the line after the include. That is a very long way from the cause, so it is
/// worth refusing up front and saying so.
pub fn preflight_path_length(destination: &Path, manifest: &Manifest) -> Result<()> {
    if !cfg!(windows) {
        return Ok(());
    }
    let base = destination.to_string_lossy().chars().count();
    let longest = manifest.keys().max_by_key(|name| name.chars().count());
    let Some(longest) = longest else { return Ok(()) };
    let total = base + 1 + longest.chars().count();
    if total > MAX_PATH {
        bail!(
            "A workspace under {} would put files {total} characters deep, past the {MAX_PATH} \
             the compilers can open (worst: {longest}). Move the project somewhere shorter.",
            destination.display()
        );
    }
    Ok(())
}

/// Copies every manifest entry into a fresh directory, verifying as it goes.
pub fn copy_snapshot(source: &Path, destination: &Path, manifest: &Manifest) -> Result<()> {
    let source = std::path::absolute(source)?;
    let destination = std::path::absolute(destination)?;
    check_ancestors(&source)?;
    check_ancestors(&destination)?;
    if destination == source || destination.strip_prefix(&source).is_ok_and(included) {
        bail!("Snapshot destination must be outside source inputs");
    }
    preflight_path_length(&destination, manifest)?;

    let mut total = 0u64;
    let mut sources = Vec::with_capacity(manifest.len());
    for relative in manifest.keys() {
        let path = safe_path(&source, relative)?;
        total += std::fs::metadata(&path)?.len();
        sources.push((relative.clone(), path));
    }
    preflight_space(destination.parent().unwrap_or(&destination), total, 1)?;

    std::fs::create_dir_all(&destination)?;
    reject_link(&destination)?;
    for (relative, path) in sources {
        let target = safe_path(&destination, &relative)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&path, &target)
            .with_context(|| format!("Failed to copy {}", path.display()))?;
        if hash_file(&target)? != manifest[&relative] {
            bail!("Input changed while snapshotting: {relative}");
        }
    }
    Ok(())
}

/// Returns an existing workspace to the baseline, keeping its build output.
///
/// Restoring only what changed is what makes a second trial fast: the compiler
/// output from the last one is still there, and Ninja rebuilds just the units
/// whose inputs moved.
pub fn reset_workspace(baseline: &Path, workspace: &Path, manifest: &Manifest) -> Result<()> {
    reset_workspace_profiled(baseline, workspace, manifest).map(|_| ())
}

/// Timings for one worker reset, excluding generated-output seeding.
#[derive(Debug, Default)]
pub struct ResetProfile {
    pub manifest_seconds: f64,
    pub baseline_verify_seconds: f64,
    pub restore_seconds: f64,
    pub removed_files: usize,
    pub restored_files: usize,
    pub restored_bytes: u64,
}

/// Resets a worker and reports where the time went without weakening validation.
pub fn reset_workspace_profiled(
    baseline: &Path,
    workspace: &Path,
    manifest: &Manifest,
) -> Result<ResetProfile> {
    let baseline = std::path::absolute(baseline)?;
    let workspace = std::path::absolute(workspace)?;
    if baseline == workspace || workspace.starts_with(&baseline) || baseline.starts_with(&workspace)
    {
        bail!("Baseline and worker must be separate directories");
    }
    check_ancestors(&workspace)?;
    std::fs::create_dir_all(&workspace)?;
    let had_build_graph = workspace.join("build.ninja").exists();
    let mut profile = ResetProfile::default();

    // Validate both trees before removing anything, so a bad manifest cannot
    // leave a half-emptied workspace behind.
    let started = Instant::now();
    let current = snapshot_manifest(&workspace)?;
    profile.manifest_seconds = started.elapsed().as_secs_f64();
    let started = Instant::now();
    for (relative, expected) in manifest {
        let source = safe_path(&baseline, relative)?;
        if &hash_file(&source)? != expected {
            bail!("Baseline changed: {relative}");
        }
        safe_path(&workspace, relative)?;
    }
    profile.baseline_verify_seconds = started.elapsed().as_secs_f64();
    let started = Instant::now();
    for relative in current.keys() {
        if !manifest.contains_key(relative) {
            std::fs::remove_file(safe_path(&workspace, relative)?)?;
            profile.removed_files += 1;
        }
    }
    for (relative, expected) in manifest {
        if current.get(relative) == Some(expected) {
            continue;
        }
        let target = safe_path(&workspace, relative)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        profile.restored_bytes += std::fs::copy(safe_path(&baseline, relative)?, &target)?;
        profile.restored_files += 1;
        // A warm workspace may hold output from a different trial. Restoring
        // an old timestamp would let Ninja treat different input bytes as up
        // to date. A fresh workspace has no such output: preserving the
        // baseline input timestamps lets its validated build cache be seeded.
        if had_build_graph {
            File::options().write(true).open(&target)?.set_modified(std::time::SystemTime::now())?;
        }
        if &hash_file(&target)? != expected {
            bail!("Baseline changed during reset: {relative}");
        }
    }
    profile.restore_seconds = started.elapsed().as_secs_f64();
    Ok(profile)
}

/// Seeds a fresh private workspace with generated outputs from a baseline
/// whose build has already been validated. The files are copied, never linked:
/// Ninja may overwrite any cached object during a trial. An existing graph
/// means this workspace has its own incremental state and must keep it.
pub fn seed_build_cache(baseline: &Path, workspace: &Path, target: &str) -> Result<()> {
    seed_build_cache_profiled(baseline, workspace, target).map(|_| ())
}

/// Time and volume spent seeding validated generated outputs.
#[derive(Debug, Default)]
pub struct SeedProfile {
    pub seconds: f64,
    pub files: usize,
    pub bytes: u64,
}

pub fn seed_build_cache_profiled(
    baseline: &Path,
    workspace: &Path,
    target: &str,
) -> Result<SeedProfile> {
    let started = Instant::now();
    let mut profile = SeedProfile::default();
    if !matches!(Path::new(target).components().collect::<Vec<_>>().as_slice(), [
        Component::Normal(_)
    ]) {
        bail!("Unsafe build cache version: {target}");
    }
    if workspace.join("build.ninja").exists() {
        return Ok(profile);
    }
    let source_build = baseline.join("build").join(target);
    if !baseline.join("build.ninja").is_file() || !source_build.is_dir() {
        return Ok(profile);
    }
    for name in ["build.ninja", ".ninja_log", ".ninja_deps"] {
        let from = baseline.join(name);
        if from.is_file() {
            reject_link(&from)?;
            let destination = workspace.join(name);
            check_ancestors(&destination)?;
            profile.bytes += std::fs::copy(&from, destination)?;
            profile.files += 1;
        }
    }
    for entry in WalkDir::new(&source_build).follow_links(false) {
        let entry = entry?;
        reject_link(entry.path())?;
        let relative = entry.path().strip_prefix(&source_build)?;
        let destination = workspace.join("build").join(target).join(relative);
        check_ancestors(&destination)?;
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&destination)?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            profile.bytes += std::fs::copy(entry.path(), &destination)?;
            profile.files += 1;
        } else {
            bail!("Build cache contains a non-file: {}", entry.path().display());
        }
    }
    profile.seconds = started.elapsed().as_secs_f64();
    Ok(profile)
}

/// A non-blocking lock on a project directory, released if the holder dies.
///
/// Migration commands share one checkout's worth of Ninja state and dtk caches.
/// Two of them at once do not fail cleanly; they produce a build whose inputs
/// nobody can reconstruct.
pub struct ProjectLock {
    _file: File,
}

impl ProjectLock {
    pub fn acquire(root: &Path) -> Result<Self> {
        let root = std::path::absolute(root)?;
        let path = safe_path(&root, LOCK_NAME)?;
        let file = File::options().create(true).read(true).append(true).open(&path)?;
        // `Ok(false)` means someone else holds it; an `Err` means we could not
        // ask. Neither is a lock, and both should stop the run.
        if !file.try_lock_exclusive().unwrap_or(false) {
            bail!("Another migration owns the project lock: {}", root.display());
        }
        Ok(Self { _file: file })
    }
}

/// User-chosen symbol mappings in `objdiff.json`, kept apart from generated
/// paths.
///
/// A person can pair two symbols by hand in objdiff, and that pairing is theirs
/// rather than the build's. It has to travel into each workspace, and a change
/// to it invalidates a run's evidence, so it is fingerprinted separately from
/// the rest of the generated file.
pub fn symbol_mappings(root: &Path) -> Result<serde_json::Value> {
    let path = root.join("objdiff.json");
    if !path.is_file() {
        return Ok(serde_json::Value::Null);
    }
    let text = std::fs::read_to_string(&path)?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    Ok(value.get("symbol_mappings").cloned().unwrap_or(serde_json::Value::Null))
}

/// Copies the generated `objdiff.json` into a fresh workspace.
///
/// It is excluded from the manifest because the build regenerates it, but a
/// workspace that starts without it cannot answer questions about comparison
/// units until the first configure has run.
pub fn seed_objdiff(source: &Path, destination: &Path) -> Result<()> {
    let from = source.join("objdiff.json");
    if from.is_file() {
        std::fs::copy(from, destination.join("objdiff.json"))?;
    }
    Ok(())
}

/// What a run recorded about the project it measured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub manifest: Manifest,
    pub mappings: serde_json::Value,
}

impl Snapshot {
    pub fn of(root: &Path) -> Result<Self> {
        Ok(Self { manifest: snapshot_manifest(root)?, mappings: symbol_mappings(root)? })
    }

    pub fn fingerprint(&self) -> Result<String> { fingerprint(self) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seeded_build_cache_is_private_and_a_warm_workspace_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let baseline = dir.path().join("baseline");
        let worker = dir.path().join("worker");
        std::fs::create_dir_all(baseline.join("build/PAL/src")).unwrap();
        std::fs::create_dir_all(&worker).unwrap();
        std::fs::write(baseline.join("build.ninja"), "graph").unwrap();
        std::fs::write(baseline.join(".ninja_log"), "log").unwrap();
        std::fs::write(baseline.join("build/PAL/src/a.o"), "original").unwrap();
        seed_build_cache(&baseline, &worker, "PAL").unwrap();
        assert_eq!(std::fs::read(worker.join("build/PAL/src/a.o")).unwrap(), b"original");
        std::fs::write(worker.join("build/PAL/src/a.o"), "changed").unwrap();
        seed_build_cache(&baseline, &worker, "PAL").unwrap();
        assert_eq!(std::fs::read(worker.join("build/PAL/src/a.o")).unwrap(), b"changed");
        assert_eq!(std::fs::read(baseline.join("build/PAL/src/a.o")).unwrap(), b"original");
        assert!(seed_build_cache(&baseline, &worker, "../PAL").is_err());
    }

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("config/PAL")).unwrap();
        std::fs::create_dir_all(root.join("build/PAL/src")).unwrap();
        std::fs::create_dir_all(root.join("build/tools")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join("configure.py"), "x = 1\n").unwrap();
        std::fs::write(root.join("config/PAL/splits.txt"), "Sections:\n\n").unwrap();
        std::fs::write(root.join("build/PAL/src/a.o"), "output").unwrap();
        std::fs::write(root.join("build/tools/dtk.exe"), "tool").unwrap();
        std::fs::write(root.join("build.ninja"), "generated").unwrap();
        std::fs::write(root.join(".git/HEAD"), "ref").unwrap();
        dir
    }

    #[test]
    fn a_manifest_holds_inputs_and_tools_but_not_output_or_history() {
        let dir = project();
        std::fs::create_dir_all(dir.path().join(".agents/state")).unwrap();
        std::fs::write(dir.path().join(".agents/state/continuation.md"), "private notes").unwrap();
        std::fs::create_dir_all(dir.path().join("config/.agents")).unwrap();
        std::fs::write(dir.path().join("config/.agents/scratch.txt"), "scratch").unwrap();
        std::fs::create_dir_all(dir.path().join("orig/PAL")).unwrap();
        std::fs::write(dir.path().join("orig/PAL/main.dol"), "retail binary").unwrap();
        let manifest = snapshot_manifest(dir.path()).unwrap();
        let names: Vec<&str> = manifest.keys().map(String::as_str).collect();
        assert!(names.contains(&"configure.py"));
        assert!(names.contains(&"config/PAL/splits.txt"));
        assert!(names.contains(&"build/tools/dtk.exe"), "the toolchain is an input");
        assert!(names.contains(&"orig/PAL/main.dol"), "retail DOLs are inputs even if ignored");
        assert!(!names.contains(&"build/PAL/src/a.o"), "build output is regenerated");
        assert!(!names.contains(&"build.ninja"), "the build graph is generated");
        assert!(!names.iter().any(|n| n.starts_with(".git")), "history is not an input");
        assert!(!names.iter().any(|n| n.split('/').any(|part| part == ".agents")));
    }

    #[test]
    fn a_fingerprint_changes_only_when_an_input_does() {
        let dir = project();
        let before = fingerprint(&snapshot_manifest(dir.path()).unwrap()).unwrap();
        std::fs::write(dir.path().join("build/PAL/src/a.o"), "different output").unwrap();
        assert_eq!(before, fingerprint(&snapshot_manifest(dir.path()).unwrap()).unwrap());
        std::fs::write(dir.path().join("configure.py"), "x = 2\n").unwrap();
        assert_ne!(before, fingerprint(&snapshot_manifest(dir.path()).unwrap()).unwrap());
    }

    #[test]
    fn a_copy_contains_every_input_and_nothing_else() {
        let dir = project();
        std::fs::create_dir_all(dir.path().join("build/compilers/GC")).unwrap();
        std::fs::write(dir.path().join("build/compilers/GC/compiler.exe"), "compiler").unwrap();
        let shared = compiler_manifest(dir.path()).unwrap();
        assert!(shared.contains_key("GC/compiler.exe"));
        std::fs::create_dir_all(dir.path().join(".agents/state")).unwrap();
        std::fs::write(dir.path().join(".agents/state/continuation.md"), "private notes").unwrap();
        let into = tempfile::tempdir().unwrap();
        let manifest = snapshot_manifest(dir.path()).unwrap();
        let destination = into.path().join("baseline");
        copy_snapshot(dir.path(), &destination, &manifest).unwrap();
        assert_eq!(snapshot_manifest(&destination).unwrap(), manifest);
        assert!(!destination.join(".agents").exists());
        assert!(!destination.join("build/compilers").exists());
        std::fs::write(dir.path().join("build/compilers/GC/compiler.exe"), "changed").unwrap();
        assert_ne!(shared, compiler_manifest(dir.path()).unwrap());
        assert_eq!(manifest, snapshot_manifest(dir.path()).unwrap());
    }

    #[test]
    fn a_copy_into_the_source_is_refused() {
        let dir = project();
        let manifest = snapshot_manifest(dir.path()).unwrap();
        let inside = dir.path().join("config/copy");
        assert!(copy_snapshot(dir.path(), &inside, &manifest).is_err());
    }

    #[test]
    fn a_reset_restores_changed_inputs_and_keeps_build_output() {
        let dir = project();
        let into = tempfile::tempdir().unwrap();
        let manifest = snapshot_manifest(dir.path()).unwrap();
        let workspace = into.path().join("worker");
        copy_snapshot(dir.path(), &workspace, &manifest).unwrap();

        // A trial edits an input and leaves compiler output behind.
        std::fs::write(workspace.join("configure.py"), "x = 999\n").unwrap();
        std::fs::create_dir_all(workspace.join("build/PAL/src")).unwrap();
        std::fs::write(workspace.join("build/PAL/src/a.o"), "trial output").unwrap();

        reset_workspace(dir.path(), &workspace, &manifest).unwrap();
        assert_eq!(std::fs::read_to_string(workspace.join("configure.py")).unwrap(), "x = 1\n");
        assert!(workspace.join("build/PAL/src/a.o").exists(), "output should survive a reset");
    }

    #[test]
    fn a_reset_removes_an_input_the_trial_added() {
        let dir = project();
        let into = tempfile::tempdir().unwrap();
        let manifest = snapshot_manifest(dir.path()).unwrap();
        let workspace = into.path().join("worker");
        copy_snapshot(dir.path(), &workspace, &manifest).unwrap();
        std::fs::write(workspace.join("config/PAL/extra.txt"), "staged").unwrap();
        reset_workspace(dir.path(), &workspace, &manifest).unwrap();
        assert!(!workspace.join("config/PAL/extra.txt").exists());
    }

    #[test]
    fn a_reset_into_the_baseline_is_refused() {
        let dir = project();
        let manifest = snapshot_manifest(dir.path()).unwrap();
        let inside = dir.path().join("worker");
        assert!(reset_workspace(dir.path(), &inside, &manifest).is_err());
    }

    #[test]
    fn a_manifest_path_that_escapes_its_root_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["../outside", "/absolute", "C:/absolute", "a\\b", "", "./a"] {
            assert!(safe_path(dir.path(), bad).is_err(), "{bad} should be refused");
        }
        assert!(safe_path(dir.path(), "config/PAL/splits.txt").is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn a_workspace_too_deep_for_the_toolchain_is_refused() {
        let manifest = Manifest::from([("a/".to_string() + &"b".repeat(250), "x".to_string())]);
        let error = preflight_path_length(Path::new("C:/deep/enough/already"), &manifest)
            .unwrap_err()
            .to_string();
        assert!(error.contains("past the 260"), "{error}");
        assert!(error.contains("Move the project"), "{error}");
    }

    #[test]
    fn a_workspace_that_fits_is_allowed() {
        let manifest = Manifest::from([("config/PAL/splits.txt".to_string(), "x".to_string())]);
        assert!(preflight_path_length(Path::new("C:/prime/build/run/baseline"), &manifest).is_ok());
    }

    #[test]
    fn a_second_lock_on_one_project_is_refused() {
        let dir = project();
        let first = ProjectLock::acquire(dir.path()).unwrap();
        assert!(ProjectLock::acquire(dir.path()).is_err());
        drop(first);
        assert!(ProjectLock::acquire(dir.path()).is_ok());
    }

    #[test]
    fn the_lock_file_is_not_itself_an_input() {
        let dir = project();
        let _lock = ProjectLock::acquire(dir.path()).unwrap();
        assert!(!snapshot_manifest(dir.path()).unwrap().contains_key(LOCK_NAME));
    }

    #[test]
    fn hand_made_symbol_mappings_are_read_separately_from_generated_paths() {
        let dir = project();
        std::fs::write(
            dir.path().join("objdiff.json"),
            r#"{"units": [{"name": "a"}], "symbol_mappings": {"fn_1": "Real"}}"#,
        )
        .unwrap();
        let mappings = symbol_mappings(dir.path()).unwrap();
        assert_eq!(mappings["fn_1"], "Real");
    }

    #[test]
    fn a_project_without_objdiff_configuration_has_no_mappings() {
        let dir = project();
        assert!(symbol_mappings(dir.path()).unwrap().is_null());
    }
}
