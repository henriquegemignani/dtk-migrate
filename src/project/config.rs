//! Where a version keeps each linked module's splits, symbols and build output.
//!
//! Most of this tool addresses the DOL and nothing else. A game that ships RELs
//! keeps whole translation units outside that view — Metroid Prime's NES
//! emulator is 34 KB of PAL code — so anything that wants to see them has to
//! ask the configuration where they live.
//!
//! Nothing about a module's location is conventional, so all of it comes from
//! `config.yml`:
//!
//! - the config directory need not match the module name (NTSC keeps
//!   `NESemuP.rel` under `config/GM8E01_00/NESemu/`),
//! - and the name need not match between versions (`NESemuP` against
//!   `NESPALemuP`),
//!
//! which is also why [`pair`] matches modules across versions by position
//! rather than by name.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use decomp_toolkit::cmd::dol::ProjectConfig;

/// The name this tool gives the main executable, which has no module entry of
/// its own.
pub const DOL_NAME: &str = "main";

/// One linked output of a version: the DOL itself, or a REL beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub root: PathBuf,
    pub version: String,
    pub name: String,
    pub splits: PathBuf,
    pub symbols: PathBuf,
    /// Where this module's build artifacts land.
    pub build: PathBuf,
    pub is_dol: bool,
}

impl Module {
    /// Compiled source objects.
    ///
    /// Shared by every module of a version: a source file compiles once into
    /// `build/<version>/src` whichever module it ends up linked into. Pairing
    /// that one tree against a module's own [`extracted`](Self::extracted)
    /// therefore selects exactly the units that module contains — and is what
    /// makes a file moving between the DOL and a REL observable, since such a
    /// move changes which `obj/` holds it and never where it compiles to.
    pub fn sources(&self) -> PathBuf { self.root.join("build").join(&self.version).join("src") }

    /// Objects split out of this module's shipped binary.
    pub fn extracted(&self) -> PathBuf { self.build.join("obj") }
}

/// Reads and parses one version's `config.yml`.
pub fn read_config(root: &Path, version: &str) -> Result<ProjectConfig> {
    let path = config_path(root, version);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_yaml::from_str(&text).with_context(|| format!("Failed to parse {}", path.display()))
}

/// The conventional location of a version's project configuration.
pub fn config_path(root: &Path, version: &str) -> PathBuf {
    root.join("config").join(version).join("config.yml")
}

/// Every module of one version, the DOL first.
///
/// A module entry without both a splits and a symbols file is skipped: there is
/// nothing for a migration to read or write, and dtk will not have split it.
pub fn modules(root: &Path, version: &str) -> Result<Vec<Module>> {
    let root = root.to_path_buf();
    let config_dir = root.join("config").join(version);
    let build_dir = root.join("build").join(version);

    let config = match read_config(&root, version) {
        Ok(config) => config,
        // A version with no configuration still has the conventional DOL paths,
        // which is enough for callers that only want to locate its files.
        Err(_) if !config_path(&root, version).is_file() => {
            return Ok(vec![Module {
                root: root.clone(),
                version: version.to_string(),
                name: DOL_NAME.to_string(),
                splits: config_dir.join("splits.txt"),
                symbols: config_dir.join("symbols.txt"),
                build: build_dir,
                is_dol: true,
            }]);
        }
        Err(e) => return Err(e),
    };

    let mut found = vec![Module {
        root: root.clone(),
        version: version.to_string(),
        name: DOL_NAME.to_string(),
        splits: config
            .base
            .splits
            .as_ref()
            .map(|p| root.join(p.as_str()))
            .unwrap_or_else(|| config_dir.join("splits.txt")),
        symbols: config
            .base
            .symbols
            .as_ref()
            .map(|p| root.join(p.as_str()))
            .unwrap_or_else(|| config_dir.join("symbols.txt")),
        build: build_dir.clone(),
        is_dol: true,
    }];

    for module in &config.modules {
        let (Some(splits), Some(symbols)) = (&module.splits, &module.symbols) else {
            continue;
        };
        // The build directory is the module object's own basename, which is
        // what dtk-template names the output directory after — not the module's
        // `name`, and not the directory its configuration happens to sit in.
        let stem = Path::new(module.object.as_str())
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        found.push(Module {
            root: root.clone(),
            version: version.to_string(),
            name: stem.clone(),
            splits: root.join(splits.as_str()),
            symbols: root.join(symbols.as_str()),
            build: build_dir.join(&stem),
            is_dol: false,
        });
    }
    Ok(found)
}

/// One module by name, defaulting to the DOL.
pub fn find(root: &Path, version: &str, name: &str) -> Result<Module> {
    let all = modules(root, version)?;
    if let Some(module) = all.iter().find(|m| m.name == name) {
        return Ok(module.clone());
    }
    let available = all.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", ");
    bail!("{version} has no module '{name}'; available: {available}")
}

/// Matches each target module to its source counterpart, by position.
///
/// Names differ across regions, so position in `config.yml` is the only stable
/// correspondence available. A target module with no counterpart is paired with
/// `None` rather than dropped: that is itself worth reporting.
pub fn pair(root: &Path, source: &str, target: &str) -> Result<Vec<(Module, Option<Module>)>> {
    let sources = modules(root, source)?;
    let targets = modules(root, target)?;
    Ok(targets.into_iter().enumerate().map(|(index, t)| (t, sources.get(index).cloned())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(config: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config").join("NTSC");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("config.yml"), config).unwrap();
        dir
    }

    const BASE: &str = "object: sys/main.dol\n\
                        symbols: config/NTSC/symbols.txt\n\
                        splits: config/NTSC/splits.txt\n";

    #[test]
    fn a_version_without_modules_is_just_its_dol() {
        let dir = project(BASE);
        let found = modules(dir.path(), "NTSC").unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].is_dol);
        assert_eq!(found[0].name, DOL_NAME);
        assert_eq!(found[0].splits, dir.path().join("config/NTSC/splits.txt"));
    }

    #[test]
    fn a_module_builds_under_its_object_basename_not_its_config_directory() {
        // Prime's NTSC config keeps NESemuP.rel's files under config/.../NESemu/
        // while the build output is named after the object.
        let dir = project(&format!(
            "{BASE}modules:\n\
             - object: files/NESemuP.rel\n  \
               symbols: config/NTSC/NESemu/symbols.txt\n  \
               splits: config/NTSC/NESemu/splits.txt\n"
        ));
        let found = modules(dir.path(), "NTSC").unwrap();
        assert_eq!(found.len(), 2);
        let rel = &found[1];
        assert_eq!(rel.name, "NESemuP");
        assert!(!rel.is_dol);
        assert_eq!(rel.build, dir.path().join("build/NTSC/NESemuP"));
        assert_eq!(rel.extracted(), dir.path().join("build/NTSC/NESemuP/obj"));
        assert_eq!(rel.splits, dir.path().join("config/NTSC/NESemu/splits.txt"));
    }

    #[test]
    fn compiled_sources_are_shared_by_every_module_of_a_version() {
        let dir = project(&format!(
            "{BASE}modules:\n\
             - object: files/NESemuP.rel\n  \
               symbols: config/NTSC/NESemu/symbols.txt\n  \
               splits: config/NTSC/NESemu/splits.txt\n"
        ));
        let found = modules(dir.path(), "NTSC").unwrap();
        assert_eq!(found[0].sources(), found[1].sources());
        assert_ne!(found[0].extracted(), found[1].extracted());
    }

    #[test]
    fn a_module_entry_without_split_files_is_skipped() {
        let dir = project(&format!("{BASE}modules:\n- object: files/Other.rel\n"));
        assert_eq!(modules(dir.path(), "NTSC").unwrap().len(), 1);
    }

    #[test]
    fn a_missing_module_names_the_ones_that_exist() {
        let dir = project(BASE);
        let error = find(dir.path(), "NTSC", "NESemuP").unwrap_err().to_string();
        assert!(error.contains("main"), "{error}");
    }
}
