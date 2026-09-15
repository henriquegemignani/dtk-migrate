//! Command-line surface. Each module here is one subcommand: its arguments and
//! the short function that turns them into a call into the library.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use decomp_toolkit::util::path::check_path_buf;
use typed_path::Utf8NativePathBuf;

pub mod configure_hook;
pub mod match_cmd;
pub mod run;
pub mod splits;
pub mod symbols;

/// Converts a path taken from the command line into the UTF-8 native path the
/// decomp-toolkit APIs use.
///
/// Paths that are not valid UTF-8 are rejected here rather than lossily
/// converted: a project path we cannot round-trip is one we cannot safely write
/// back into a configuration file.
pub fn native(path: &Path) -> Result<Utf8NativePathBuf> {
    check_path_buf(path.to_path_buf())
        .map_err(|e| anyhow!("Path is not valid UTF-8: {} ({e})", path.display()))
}

/// Same, for an optional argument.
pub fn native_opt(path: Option<&PathBuf>) -> Result<Option<Utf8NativePathBuf>> {
    path.map(|p| native(p)).transpose()
}
