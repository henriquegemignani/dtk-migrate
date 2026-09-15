//! Private copies of the game project, and proof that they are what we think.
//!
//! A trial has to compile, which means it has to write into a project. Doing
//! that in the user's checkout would make every run a race with whatever else
//! they are doing, so each worker gets its own copy and the coordinator keeps
//! the original untouched until there is something proven to publish.
//!
//! What gets copied is the *current* state of the checkout, not committed HEAD:
//! dirty files and untracked ones are exactly what someone wants tested. Each
//! file is hashed on the way in, so a later run can say whether the thing it
//! measured is still the thing on disk.

use std::{
    collections::BTreeMap,
    fs::File,
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use fs4::fs_std::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

pub const LOCK_NAME: &str = ".migration.lock";

/// Directories that are caches or history rather than build inputs.
const CACHE_NAMES: [&str; 9] = [
    ".git",
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
const TOOL_DIRS: [&str; 3] = ["compilers", "tools", "binutils"];

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
        // Build output is regenerated; the downloaded toolchain is not.
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

/// Copies every manifest entry into a fresh directory, verifying as it goes.
pub fn copy_snapshot(source: &Path, destination: &Path, manifest: &Manifest) -> Result<()> {
    let source = std::path::absolute(source)?;
    let destination = std::path::absolute(destination)?;
    check_ancestors(&source)?;
    check_ancestors(&destination)?;
    if destination == source
        || destination.strip_prefix(&source).is_ok_and(|relative| included(relative))
    {
        bail!("Snapshot destination must be outside source inputs");
    }

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
    let baseline = std::path::absolute(baseline)?;
    let workspace = std::path::absolute(workspace)?;
    if baseline == workspace || workspace.starts_with(&baseline) || baseline.starts_with(&workspace)
    {
        bail!("Baseline and worker must be separate directories");
    }
    check_ancestors(&workspace)?;
    std::fs::create_dir_all(&workspace)?;

    // Validate both trees before removing anything, so a bad manifest cannot
    // leave a half-emptied workspace behind.
    let current = snapshot_manifest(&workspace)?;
    for (relative, expected) in manifest {
        let source = safe_path(&baseline, relative)?;
        if &hash_file(&source)? != expected {
            bail!("Baseline changed: {relative}");
        }
        safe_path(&workspace, relative)?;
    }
    for relative in current.keys() {
        if !manifest.contains_key(relative) {
            std::fs::remove_file(safe_path(&workspace, relative)?)?;
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
        std::fs::copy(safe_path(&baseline, relative)?, &target)?;
        // Cached output may describe a previous trial. Restoring an old
        // timestamp would let Ninja treat different input bytes as up to date.
        File::options().write(true).open(&target)?.set_modified(std::time::SystemTime::now())?;
        if &hash_file(&target)? != expected {
            bail!("Baseline changed during reset: {relative}");
        }
    }
    Ok(())
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
        let manifest = snapshot_manifest(dir.path()).unwrap();
        let names: Vec<&str> = manifest.keys().map(String::as_str).collect();
        assert!(names.contains(&"configure.py"));
        assert!(names.contains(&"config/PAL/splits.txt"));
        assert!(names.contains(&"build/tools/dtk.exe"), "the toolchain is an input");
        assert!(!names.contains(&"build/PAL/src/a.o"), "build output is regenerated");
        assert!(!names.contains(&"build.ninja"), "the build graph is generated");
        assert!(!names.iter().any(|n| n.starts_with(".git")), "history is not an input");
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
        let into = tempfile::tempdir().unwrap();
        let manifest = snapshot_manifest(dir.path()).unwrap();
        let destination = into.path().join("baseline");
        copy_snapshot(dir.path(), &destination, &manifest).unwrap();
        assert_eq!(snapshot_manifest(&destination).unwrap(), manifest);
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
