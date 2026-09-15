//! The dtk-template project on disk: its configuration, its splits and symbol
//! files, its build report, and the `configure.py` that decides which units
//! link from source.
//!
//! Every file here is a project *input* that a migration may rewrite, so each
//! module keeps read and write together and refuses to write something it could
//! not parse.

pub mod analyze;
pub mod split_merge;
pub mod symbols;
