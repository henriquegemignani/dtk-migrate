//! Cross-version analysis: what a function is, which function in the other
//! version it is, and which translation unit a run of them belongs to.
//!
//! Everything here reads two analysed executables and produces evidence. None
//! of it edits a project; that is the job of [`crate::stages`], which takes
//! this evidence, tries it, and keeps only what the build agrees with.

pub mod boundaries;
pub mod callgraph;
pub mod coverage;
pub mod coverage_fixture;
pub mod data_matching;
pub mod fingerprint;
pub mod mask;
pub mod matching;
pub mod ownership;
pub mod ownership_score;
pub mod policy;
pub mod unit_matching;
pub mod unit_runs;
