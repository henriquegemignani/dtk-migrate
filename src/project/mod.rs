//! The dtk-template project on disk: its configuration, its splits and symbol
//! files, its build report, and the `configure.py` that decides which units
//! link from source.
//!
//! Every file here is a project *input* that a migration may rewrite, so each
//! module keeps read and write together and refuses to write something it could
//! not parse.

pub mod analyze;
pub mod config;
pub mod configure_py;
pub mod pysyntax;
pub mod report;
pub mod split_merge;
pub mod splits;
pub mod symbols;
