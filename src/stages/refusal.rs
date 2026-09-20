//! A refusal is classified from the failing command, never from a shared log.

use std::{
    io::{Read, Seek, SeekFrom},
    sync::LazyLock,
};

use anyhow::Error;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::build::{
    context::ValidationError,
    process::{CommandError, CommandEvidence},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    ConflictingAttribution,
    IllegalSplit,
    SplitAlignment,
    LinkOrderCycle,
    UndefinedSymbol,
    DuplicateSymbol,
    SourceCompileError,
    RetailMismatch,
    MeasuredRegression,
    Timeout,
    UnavailableInput,
    StalePrecondition,
    DependencyNotPermitted,
    SourceLinkageViolation,
    Unknown,
}

impl Kind {
    /// Retain the historical event prefix while reports transition to typed kinds.
    pub fn legacy_category(self) -> &'static str {
        match self {
            Self::ConflictingAttribution => "ownership-preflight",
            Self::IllegalSplit => "ownership-preflight",
            Self::SplitAlignment => "split-alignment",
            Self::LinkOrderCycle => "link-order-cycle",
            Self::UndefinedSymbol => "undefined-symbol",
            Self::DuplicateSymbol => "duplicate-symbol",
            Self::SourceCompileError => "compilation-failure",
            Self::RetailMismatch => "retail-mismatch",
            Self::MeasuredRegression => "regression",
            Self::Timeout => "build-timeout",
            Self::UnavailableInput => "unavailable-input",
            Self::StalePrecondition => "stale-precondition",
            Self::DependencyNotPermitted => "dependency-not-permitted",
            Self::SourceLinkageViolation => "source-linkage-violation",
            Self::Unknown => "unknown-failure",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refusal {
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected: Vec<String>,
    /// The complete log span and bounded output of this command only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<CommandEvidence>,
}

impl Refusal {
    pub fn from_error(error: &Error) -> Self {
        if let Some(command) = error.chain().find_map(|cause| cause.downcast_ref::<CommandError>())
        {
            let evidence = command.evidence().cloned();
            let (kind, affected) = match command {
                CommandError::TimedOut { .. } => (Kind::Timeout, Vec::new()),
                CommandError::Failed { .. } => {
                    evidence.as_ref().map_or((Kind::Unknown, Vec::new()), |e| {
                        classify(&command_output(e).unwrap_or_else(|| {
                            format!("{}\n{}", e.stdout_excerpt, e.stderr_excerpt)
                        }))
                    })
                }
                // Cancellation and I/O errors must stop the run; callers must
                // never turn them into a refusal.
                CommandError::Cancelled | CommandError::Io(_) => (Kind::Unknown, Vec::new()),
            };
            return Self { kind, affected, command: evidence };
        }
        let text = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<ValidationError>().map(|e| e.0.as_str()))
            .map(str::to_string)
            .unwrap_or_else(|| format!("{error:#}"));
        let (kind, affected) = classify(&text);
        Self { kind, affected, command: None }
    }
}

/// Read just this invocation's span. Excerpts are for persisted diagnostics;
/// a linker error in the middle of a long command must still be classified.
fn command_output(evidence: &CommandEvidence) -> Option<String> {
    let length = evidence.log_end.checked_sub(evidence.log_start)?;
    let mut log = std::fs::File::open(&evidence.log).ok()?;
    log.seek(SeekFrom::Start(evidence.log_start)).ok()?;
    let mut bytes = Vec::new();
    log.take(length).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 != length {
        return None;
    }
    // The first line is the command invocation, not its diagnostics. Its
    // arguments may themselves contain words such as "undefined symbol".
    let first_newline = bytes.iter().position(|byte| *byte == b'\n')?;
    let output = &bytes[first_newline + 1..];
    Some(String::from_utf8_lossy(output).into_owned())
}

static SYMBOL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:undefined symbol|duplicate symbol|multiply defined)(?:[ \t]*:[ \t]*|[ \t]+)['`\"]?([^\s,:'`\";][^\s,'`\";]*)"#)
        .expect("valid symbol regex")
});
static UNIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9_./\\-]+\.(?:cpp|c|o)\b").expect("valid unit regex"));

fn classify(text: &str) -> (Kind, Vec<String>) {
    let lower = text.to_ascii_lowercase();
    let has = |needle: &str| lower.contains(needle);
    let kind = if has("timed out after") {
        Kind::Timeout
    } else if has("retail dol bytes differ")
        || has("checksum mismatch")
        || has("checksum failed")
        || has("sha1 mismatch")
        || has("hash mismatch")
    {
        Kind::RetailMismatch
    } else if has("link-order cycle") || has("cyclic dependency") {
        Kind::LinkOrderCycle
    } else if has("stale precondition") {
        Kind::StalePrecondition
    } else if has("which this run does not permit") {
        Kind::DependencyNotPermitted
    } else if has("would overlap") || has("overlaps another") || has("conflicting attribution") {
        Kind::ConflictingAttribution
    } else if has("invalid alignment") || has("split alignment") {
        Kind::SplitAlignment
    } else if has("transaction refused") || has("illegal split") {
        Kind::IllegalSplit
    } else if has("multiply defined") || has("multiply-defined") || has("duplicate symbol") {
        Kind::DuplicateSymbol
    } else if has("undefined:") || has("undefined symbol") {
        Kind::UndefinedSymbol
    } else if has("compiled source object was enabled") || has("extracted target object is not") {
        Kind::SourceLinkageViolation
    } else if has("regresses an existing unit") || has("reduces source-linked code") {
        Kind::MeasuredRegression
    } else if has("cannot open") || has("no such file") || has("file not found") {
        Kind::UnavailableInput
    } else if has("fatal error") || has("error:") || has("error #") {
        Kind::SourceCompileError
    } else {
        Kind::Unknown
    };
    let mut affected = Vec::new();
    for captures in SYMBOL.captures_iter(text) {
        let symbol = captures[1].trim_end_matches(['.', ':', ')']);
        if !symbol.is_empty() && !affected.iter().any(|seen| seen == symbol) {
            affected.push(symbol.to_string());
        }
    }
    for unit in UNIT.find_iter(text) {
        let name = unit.as_str();
        if !affected.iter().any(|seen| seen == name) {
            affected.push(name.to_string());
        }
    }
    affected.truncate(16);
    (kind, affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_command_is_classified_only_from_its_own_output() {
        let evidence = CommandEvidence {
            program: "ninja".into(),
            args: vec!["all".into()],
            log: "build.log".into(),
            log_start: 100,
            log_end: 200,
            stdout_excerpt: String::new(),
            stderr_excerpt: "undefined symbol: MissingAnim in Pane.cpp".into(),
        };
        let error = Error::new(CommandError::Failed {
            status: Some(1),
            evidence: Some(Box::new(evidence)),
        })
        .context("previous trial had a checksum failure");
        let refusal = Refusal::from_error(&error);
        assert_eq!(refusal.kind, Kind::UndefinedSymbol);
        assert_eq!(refusal.affected, ["MissingAnim", "Pane.cpp"]);
        assert_eq!(refusal.command.unwrap().log_start, 100);
    }

    #[test]
    fn an_unclassified_command_does_not_borrow_a_prior_failure() {
        let evidence = CommandEvidence {
            program: "ninja".into(),
            args: vec![],
            log: "build.log".into(),
            log_start: 200,
            log_end: 300,
            stdout_excerpt: String::new(),
            stderr_excerpt: "ninja: build stopped: subcommand failed".into(),
        };
        let error = Error::new(CommandError::Failed {
            status: Some(1),
            evidence: Some(Box::new(evidence)),
        })
        .context("old log contained undefined symbol: Obsolete");
        assert_eq!(Refusal::from_error(&error).kind, Kind::Unknown);
    }

    #[test]
    fn a_missing_symbol_name_does_not_consume_the_next_log_line() {
        let (kind, affected) = classify("undefined symbol:\nninja: build stopped");
        assert_eq!(kind, Kind::UndefinedSymbol);
        assert!(affected.is_empty());
    }

    #[test]
    fn a_compiler_error_in_a_checksum_named_file_is_not_a_retail_mismatch() {
        let (kind, affected) = classify("checksum.cpp:34: error: unknown type name");
        assert_eq!(kind, Kind::SourceCompileError);
        assert_eq!(affected, ["checksum.cpp"]);
    }

    #[test]
    fn a_middle_diagnostic_is_found_without_reading_an_adjacent_command() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("build.log");
        let first = "+ ninja old\nundefined symbol: Old\n! exit status 1\n";
        let second = format!(
            "+ ninja new\n{}undefined symbol: MissingAnim in Pane.cpp\n{}! exit status 1\n",
            "filler\n".repeat(700),
            "filler\n".repeat(700)
        );
        std::fs::write(&log, format!("{first}{second}")).unwrap();
        let evidence = CommandEvidence {
            program: "ninja".into(),
            args: vec!["new".into()],
            log,
            log_start: first.len() as u64,
            log_end: (first.len() + second.len()) as u64,
            stdout_excerpt: "filler\n".into(),
            stderr_excerpt: String::new(),
        };
        let error = Error::new(CommandError::Failed {
            status: Some(1),
            evidence: Some(Box::new(evidence)),
        });
        let refusal = Refusal::from_error(&error);
        assert_eq!(refusal.kind, Kind::UndefinedSymbol);
        assert_eq!(refusal.affected, ["MissingAnim", "Pane.cpp"]);
    }
}
