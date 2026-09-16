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
//! 1. **Split coverage** — a target address range is assigned to a source file.
//!    This says nothing about whether that file compiles or matches.
//! 2. **Objdiff matched code** — bytes in functions a comparison calls matching.
//!    A partly finished file still contributes.
//! 3. **Configured source linkage** — the file is enabled in `configure.py`.
//!    That is a build setting, not a measurement.
//! 4. **Verified source linkage** — the compiled object is an actual input to
//!    the linker and the resulting executable equals retail. This is the only
//!    whole-file proof.

pub mod analysis;
pub mod build;
pub mod cli;
pub mod derive;
pub mod matching;
pub mod project;
pub mod run;
pub mod stages;
pub mod workspace;
