//! All integration tests, built as one binary.
//!
//! One binary links the crate once instead of once per suite, and lets the
//! slow fixture suites run in parallel instead of one binary at a time.
//! Run one suite with `cargo test --test integration <module>::`.

mod common;

mod cascade;
mod compiled_call_tail;
mod composed_stages;
mod discover_parallel;
mod emitted_owner;
mod helper_identification;
mod historical_recall;
mod joint_runs;
mod object_evidence;
mod pipeline;
mod real_project;
mod relocation_pairing;
mod relocation_run;
mod transactions;
mod verify_feedback;
mod verify_parallel;
