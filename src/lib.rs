//! Cross-version split discovery and source migration for decomp-toolkit
//! projects.
//!
//! The tool takes a decompilation project that has two versions of the same
//! executable, one partly matched and one not, and moves progress from the
//! first to the second: symbol names, split boundaries, and finally whole
//! source files. Nothing is kept on the strength of a proposal alone. Every
//! change is applied to a private copy of the project, compiled, measured, and
//! discarded unless the build agrees with it.
//!
//! The four questions the tool keeps separate, weakest evidence first:
//!
//! 1. **Binary TU identification** — target functions are attributed to a
//!    source translation unit, with competing explanations retained.
//! 2. **Boundary recovery** — evidence supports both ends of a target range.
//!    This alone does not make it safe to apply.
//! 3. **Applied ownership** — a target range is assigned to a source file and
//!    survives a build. This says nothing about whether that file compiles.
//! 4. **Verified source linkage** — the compiled object is an actual input to
//!    the linker and the resulting executable equals retail. This is the only
//!    whole-file proof.
//!
//! Objdiff matched-code percentage is a separate function comparison;
//! `configure.py` linkage is a build setting, not a measurement.

pub mod analysis;
pub mod build;
pub mod cli;
pub mod derive;
pub mod matching;
pub mod project;
pub mod run;
pub mod stages;
pub mod workspace;
