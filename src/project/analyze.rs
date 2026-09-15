//! Getting from a project configuration to an analysed executable.
//!
//! Every command that compares two versions starts here: read `config.yml`,
//! find the extracted originals it points at, run dtk's DOL analysis, then let
//! the relocation tracker populate the references the matcher reads as call
//! edges.

use std::{env, fs};

use anyhow::{Context, Result, anyhow, bail};
use decomp_toolkit::{
    analysis::tracker::Tracker,
    cmd::dol::{ObjectBase, ProjectConfig, find_object_base, load_analyze_dol},
    obj::ObjInfo,
    util::path::check_path_buf,
    vfs::open_file,
};
use typed_path::{Utf8NativePath, Utf8NativePathBuf};

use crate::analysis::coverage::ExtractSpec;

/// Serialises everything that depends on the process working directory.
///
/// A project configuration's paths are written relative to its own root, and
/// dtk resolves them against the working directory. That is fine for a command
/// that loads one project, but this tool runs several workers as threads in one
/// process, and the working directory is shared by all of them. Holding this
/// for the whole of a load means at most one thread is ever inside that window.
///
/// Child processes are unaffected either way: every command this tool starts is
/// given its directory explicitly.
static CWD: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runs the standard DOL analysis pipeline, up to and including relocation
/// tracking, which is what populates the call edges the matcher relies on.
pub fn load_analyzed(
    config_path: &Utf8NativePath,
    root: Option<&Utf8NativePath>,
    root_option: &str,
) -> Result<(ProjectConfig, ObjInfo)> {
    // Poisoning only means some other load panicked; the directory is restored
    // by its guard either way, so there is nothing unsafe to inherit.
    let _serialized = CWD.lock().unwrap_or_else(|e| e.into_inner());
    let config: ProjectConfig = {
        let mut file = open_file(config_path, true)?;
        serde_yaml::from_reader(file.as_mut())?
    };
    // Must be resolved before entering the root, since it probes relative paths
    // against the working directory.
    let root = resolve_project_root(&config, config_path, root, root_option)?;
    let _guard = root.map(WorkingDirectory::enter).transpose()?;

    let object_base: ObjectBase = find_object_base(&config)?;
    let mut obj = load_analyze_dol(&config, &object_base)?.obj;

    let mut tracker = Tracker::new(&obj);
    tracker.process(&obj)?;
    tracker.apply(&mut obj, false)?;
    Ok((config, obj))
}

pub fn extract_specs(config: &ProjectConfig) -> Vec<ExtractSpec> {
    config
        .base
        .extract
        .iter()
        .map(|extract| ExtractSpec {
            symbol: extract.symbol.clone(),
            rename: extract.rename.clone(),
            binary: extract.binary.as_ref().map(ToString::to_string),
            header: extract.header.as_ref().map(ToString::to_string),
            relocations: extract.relocations.as_ref().map(ToString::to_string),
            header_type: extract.header_type.clone(),
            custom_type: extract.custom_type.clone(),
            custom_data: extract.custom_data.clone(),
        })
        .collect()
}

/// Finds the directory a configuration's relative paths are written against.
///
/// Every other dtk command resolves these against the working directory, which
/// is fine when a command operates on a single project. `match` takes two, and
/// they may live in separate repositories, so `-C` can't serve both. Returns
/// `None` when the working directory already works, leaving behavior untouched.
fn resolve_project_root(
    config: &ProjectConfig,
    config_path: &Utf8NativePath,
    override_root: Option<&Utf8NativePath>,
    root_option: &str,
) -> Result<Option<Utf8NativePathBuf>> {
    if let Some(root) = override_root {
        return Ok(Some(root.to_path_buf()));
    }
    // A path the configuration names that must exist under the correct root.
    let probe =
        config.object_base.clone().unwrap_or_else(|| config.base.object.clone()).with_encoding();
    if fs::metadata(&probe).is_ok() {
        return Ok(None);
    }
    // Walk up from the configuration itself, so an absolute path to a config in
    // another project resolves without having to change directory first.
    let mut directory = config_path.parent();
    while let Some(current) = directory {
        if fs::metadata(current.join(&probe)).is_ok() {
            return Ok(Some(current.to_path_buf()));
        }
        directory = current.parent();
    }
    bail!(
        "Couldn't locate '{probe}' from the working directory or anywhere above {config_path}.\n\
         Run from the project root, or pass {root_option} <dir>."
    )
}

/// Enters a directory, restoring the previous one when dropped.
///
/// A project configuration's paths are written relative to its own root, and the
/// rest of dtk resolves them against the working directory. Rather than rewriting
/// every path a configuration can carry, load each project from where its paths
/// were meant to be read. Loads are sequential; this would need revisiting if
/// they were ever run in parallel.
struct WorkingDirectory(Utf8NativePathBuf);

impl WorkingDirectory {
    fn enter(path: Utf8NativePathBuf) -> Result<Self> {
        let previous = check_path_buf(env::current_dir()?)
            .map_err(|e| anyhow!("Working directory is not valid UTF-8: {e}"))?;
        env::set_current_dir(&path)
            .with_context(|| format!("Failed to change working directory to '{path}'"))?;
        Ok(Self(previous))
    }
}

impl Drop for WorkingDirectory {
    fn drop(&mut self) {
        if let Err(e) = env::set_current_dir(&self.0) {
            tracing::warn!("Failed to restore working directory '{}': {e}", self.0);
        }
    }
}
