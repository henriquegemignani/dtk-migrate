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
    /// The linker's own symbol diagnostics, one per distinct message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub linker: Vec<LinkerDiagnostic>,
    /// The complete log span and bounded output of this command only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<CommandEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkerDiagnosticKind {
    MultiplyDefined,
    Undefined,
}

/// One `mwld` symbol error. The symbol is spelled as the linker prints it,
/// which for C++ is the demangled form (`CClass::sMember`), not the
/// `symbols.txt` name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LinkerDiagnostic {
    pub kind: LinkerDiagnosticKind,
    pub symbol: String,
    /// The object that defines (multiply-defined) or references (undefined)
    /// the symbol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Where an undefined symbol is referenced from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referenced_from: Option<String>,
    /// The object that already defined a multiply-defined symbol, such as an
    /// unsplit `auto_09_8041BEB8_sdata.o` gap object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previously_defined_in: Option<String>,
}

impl Refusal {
    pub fn from_error(error: &Error) -> Self {
        if let Some(command) = error.chain().find_map(|cause| cause.downcast_ref::<CommandError>())
        {
            let evidence = command.evidence().cloned();
            let (kind, affected, linker) = match command {
                CommandError::TimedOut { .. } => (Kind::Timeout, Vec::new(), Vec::new()),
                CommandError::Failed { .. } => {
                    evidence.as_ref().map_or((Kind::Unknown, Vec::new(), Vec::new()), |e| {
                        classify(&command_output(e).unwrap_or_else(|| {
                            format!("{}\n{}", e.stdout_excerpt, e.stderr_excerpt)
                        }))
                    })
                }
                // Cancellation and I/O errors must stop the run; callers must
                // never turn them into a refusal.
                CommandError::Cancelled | CommandError::Io(_) => {
                    (Kind::Unknown, Vec::new(), Vec::new())
                }
            };
            return Self { kind, affected, linker, command: evidence };
        }
        let text = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<ValidationError>().map(|e| e.0.as_str()))
            .map(str::to_string)
            .unwrap_or_else(|| format!("{error:#}"));
        let (kind, affected, linker) = classify(&text);
        Self { kind, affected, linker, command: None }
    }

    /// Multiply-defined symbols whose earlier definition is an unsplit gap
    /// object, as (symbol, gap object).
    pub fn gap_duplicates(&self) -> impl Iterator<Item = (&str, &str)> {
        self.linker.iter().filter_map(|diagnostic| {
            let previous = diagnostic.previously_defined_in.as_deref()?;
            (diagnostic.kind == LinkerDiagnosticKind::MultiplyDefined
                && previous.starts_with("auto_"))
            .then_some((diagnostic.symbol.as_str(), previous))
        })
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
static MULTIPLY_DEFINED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^multiply-defined: '(.+?)' in (\S+) Previously defined in (\S+)$")
        .expect("valid multiply-defined regex")
});
static UNDEFINED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^undefined: '(.+?)'(?: Referenced from '(.+?)' in (\S+))?$")
        .expect("valid undefined regex")
});

/// Distinct diagnostics kept per refusal and kind. One unit can repeat the
/// same undefined reference hundreds of times; a separate cap per kind keeps
/// those from crowding out the duplicates link feedback reads.
const MAX_LINKER_DIAGNOSTICS: usize = 64;

/// Continuation lines beyond which a message is only rejoined at spaces.
const MAX_REJOINED_LINES: usize = 8;

/// `mwld` prints each message as a `###` header followed by `#`-prefixed
/// lines, wrapping long ones, normally at a space:
///
/// ```text
/// ### mwldeppc.exe Linker Error:
/// #   multiply-defined: 'CDolphinController::skTypeUnknown' in
/// #   CDolphinController.o
/// #   Previously defined in auto_11_80421AB8_sdata2.o
/// ```
///
/// Rejoining a message's lines with single spaces restores the original
/// text. A token too long for one line is cut without a space, so a message
/// that does not parse that way is also tried with some joins closed up,
/// fewest first.
fn linker_diagnostics(text: &str) -> Vec<LinkerDiagnostic> {
    let mut messages: Vec<Vec<&str>> = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in text.lines().map(str::trim_end) {
        if line.starts_with("###") {
            messages.extend(current.replace(Vec::new()));
        } else if let (Some(body), Some(message)) = (line.strip_prefix('#'), current.as_mut()) {
            let body = body.trim();
            if !body.is_empty() {
                message.push(body);
            }
        } else {
            messages.extend(current.take());
        }
    }
    messages.extend(current);

    let mut diagnostics: Vec<LinkerDiagnostic> = Vec::new();
    let mut counts = [0usize; 2];
    for pieces in &messages {
        let Some(diagnostic) = rejoinings(pieces).find_map(|message| parse_diagnostic(&message))
        else {
            continue;
        };
        let count = &mut counts[diagnostic.kind as usize];
        if *count < MAX_LINKER_DIAGNOSTICS && !diagnostics.contains(&diagnostic) {
            *count += 1;
            diagnostics.push(diagnostic);
        }
    }
    diagnostics
}

/// The ways to rejoin a wrapped message: every join a space first, then
/// with one join closed up, then two, and so on.
fn rejoinings<'a>(pieces: &'a [&'a str]) -> impl Iterator<Item = String> + 'a {
    let joins = pieces.len().saturating_sub(1);
    let masks: Vec<u32> = if joins == 0 || joins >= MAX_REJOINED_LINES {
        vec![0]
    } else {
        let mut masks: Vec<u32> = (0..1u32 << joins).collect();
        masks.sort_by_key(|mask| mask.count_ones());
        masks
    };
    masks.into_iter().map(move |closed| {
        let mut message = String::new();
        for (index, piece) in pieces.iter().enumerate() {
            if index > 0 && closed & (1 << (index - 1)) == 0 {
                message.push(' ');
            }
            message.push_str(piece);
        }
        message
    })
}

fn parse_diagnostic(message: &str) -> Option<LinkerDiagnostic> {
    if let Some(found) = MULTIPLY_DEFINED.captures(message) {
        Some(LinkerDiagnostic {
            kind: LinkerDiagnosticKind::MultiplyDefined,
            symbol: found[1].to_string(),
            object: Some(found[2].to_string()),
            referenced_from: None,
            previously_defined_in: Some(found[3].to_string()),
        })
    } else {
        UNDEFINED.captures(message).map(|found| LinkerDiagnostic {
            kind: LinkerDiagnosticKind::Undefined,
            symbol: found[1].to_string(),
            object: found.get(3).map(|object| object.as_str().to_string()),
            referenced_from: found.get(2).map(|from| from.as_str().to_string()),
            previously_defined_in: None,
        })
    }
}

fn classify(text: &str) -> (Kind, Vec<String>, Vec<LinkerDiagnostic>) {
    let lower = text.to_ascii_lowercase();
    let has = |needle: &str| lower.contains(needle);
    let kind = if has("timed out after") {
        Kind::Timeout
    } else if has("retail dol bytes differ")
        || has("checksum mismatch")
        || has("checksum failed")
        || has("computed checksum(s) did not match")
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
    let linker = linker_diagnostics(text);
    let mut affected: Vec<String> = Vec::new();
    for diagnostic in &linker {
        for name in std::iter::once(&diagnostic.symbol).chain(&diagnostic.previously_defined_in) {
            if !affected.contains(name) {
                affected.push(name.clone());
            }
        }
    }
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
    (kind, affected, linker)
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
        let (kind, affected, _) = classify("undefined symbol:\nninja: build stopped");
        assert_eq!(kind, Kind::UndefinedSymbol);
        assert!(affected.is_empty());
    }

    #[test]
    fn a_compiler_error_in_a_checksum_named_file_is_not_a_retail_mismatch() {
        let (kind, affected, _) = classify("checksum.cpp:34: error: unknown type name");
        assert_eq!(kind, Kind::SourceCompileError);
        assert_eq!(affected, ["checksum.cpp"]);
    }

    /// Abridged from a G2MJ01 verify trial of `Kyoto/Input/CDolphinController.cpp`
    /// and `musyx/runtime/seq.c`, including mwld's wrapping and CRLF endings.
    const MWLD_DUPLICATES: &str = "[1/4] LINK build\\G2MJ01\\main.elf\r\n\
        FAILED: [code=1] build/G2MJ01/main.elf \r\n\
        ### build\\compilers\\GC\\2.7\\mwldeppc.exe Linker Error:\r\n\
        #   multiply-defined: 'CDolphinController::skTypeUnknown' in \r\n\
        #   CDolphinController.o\r\n\
        #   Previously defined in auto_11_80421AB8_sdata2.o\r\n\
        ### build\\compilers\\GC\\2.7\\mwldeppc.exe Linker Error:\r\n\
        #   multiply-defined: 'seqFreeRoot' in seq.o\r\n\
        #   Previously defined in auto_10_8041D0A8_sbss.o\r\n\
        ### build\\compilers\\GC\\2.7\\mwldeppc.exe Linker Error:\r\n\
        #   multiply-defined: 'seqFreeRoot' in seq.o\r\n\
        #   Previously defined in auto_10_8041D0A8_sbss.o\r\n\
        ### build\\compilers\\GC\\2.7\\mwldeppc.exe Linker Warning:\r\n\
        #   FORCEACTIVE symbol '__sinit_CEulerAngles_cpp' is either not a global \r\n\
        #   symbol or doesn't exist.  Ignored.\r\n\
        ### build\\compilers\\GC\\2.7\\mwldeppc.exe Linker Error:\r\n\
        #   undefined: 'HandleEvent'\r\n\
        #   Referenced from '@1689_803C2D68' in auto_07_803C2C78_data.o\r\n\
        ### build\\compilers\\GC\\2.7\\mwldeppc.exe Linker Alert:\r\n\
        #   Link failed.\r\n\
        \r\n\
        Errors caused tool to abort.\r\n\
        ninja: build stopped: subcommand failed.";

    #[test]
    fn wrapped_mwld_symbol_errors_keep_their_symbol_and_objects() {
        let (kind, affected, linker) = classify(MWLD_DUPLICATES);
        assert_eq!(kind, Kind::DuplicateSymbol);
        assert_eq!(linker.len(), 3, "a repeated message is recorded once: {linker:?}");
        assert_eq!(linker[0], LinkerDiagnostic {
            kind: LinkerDiagnosticKind::MultiplyDefined,
            symbol: "CDolphinController::skTypeUnknown".into(),
            object: Some("CDolphinController.o".into()),
            referenced_from: None,
            previously_defined_in: Some("auto_11_80421AB8_sdata2.o".into()),
        });
        assert_eq!(linker[1].symbol, "seqFreeRoot");
        assert_eq!(linker[2], LinkerDiagnostic {
            kind: LinkerDiagnosticKind::Undefined,
            symbol: "HandleEvent".into(),
            object: Some("auto_07_803C2C78_data.o".into()),
            referenced_from: Some("@1689_803C2D68".into()),
            previously_defined_in: None,
        });
        assert_eq!(&affected[..4], [
            "CDolphinController::skTypeUnknown",
            "auto_11_80421AB8_sdata2.o",
            "seqFreeRoot",
            "auto_10_8041D0A8_sbss.o",
        ]);
        let refusal = Refusal { kind, affected, linker, command: None };
        assert_eq!(refusal.gap_duplicates().collect::<Vec<_>>(), [
            ("CDolphinController::skTypeUnknown", "auto_11_80421AB8_sdata2.o"),
            ("seqFreeRoot", "auto_10_8041D0A8_sbss.o"),
        ]);
    }

    #[test]
    fn a_token_cut_mid_line_and_a_bare_continuation_still_parse() {
        let linker = linker_diagnostics(
            "### mwldeppc.exe Linker Error:\n\
             #   multiply-defined: 'CStateManager::skValue' in CStateManager.o\n\
             #\n\
             #   Previously defined in auto_03_8040\n\
             #   0000_sdata.o\n",
        );
        assert_eq!(linker, [LinkerDiagnostic {
            kind: LinkerDiagnosticKind::MultiplyDefined,
            symbol: "CStateManager::skValue".into(),
            object: Some("CStateManager.o".into()),
            referenced_from: None,
            previously_defined_in: Some("auto_03_80400000_sdata.o".into()),
        }]);
        // Inside the quoted name a cut cannot be told from a real space; the
        // name keeps the space and link feedback compares without spaces.
        let linker = linker_diagnostics(
            "### mwldeppc.exe Linker Error:\n\
             #   multiply-defined: 'CStateManager::skLong\n\
             #   Name' in CStateManager.o\n\
             #   Previously defined in auto_03_80400000_sdata.o\n",
        );
        assert_eq!(linker[0].symbol, "CStateManager::skLong Name");
    }

    #[test]
    fn many_undefined_references_do_not_crowd_out_duplicates() {
        let mut text = String::new();
        for index in 0..100 {
            text.push_str(&format!(
                "### mwldeppc.exe Linker Error:\n#   undefined: 'Missing{index}'\n"
            ));
        }
        text.push_str(
            "### mwldeppc.exe Linker Error:\n\
             #   multiply-defined: 'sValue' in unit.o\n\
             #   Previously defined in auto_01_80001000_data.o\n",
        );
        let linker = linker_diagnostics(&text);
        let undefined = linker.iter().filter(|d| d.kind == LinkerDiagnosticKind::Undefined).count();
        assert_eq!(undefined, MAX_LINKER_DIAGNOSTICS);
        assert_eq!(linker.last().unwrap().symbol, "sValue");
    }

    #[test]
    fn a_failed_dtk_shasum_is_a_retail_mismatch() {
        // The tail of a G2MJ01 verify trial of `musyx/runtime/snd3d.c`.
        let (kind, _, linker) = classify(
            "[3/4] CHECK config\\G2MJ01\\build.sha1\r\n\
             FAILED: [code=1] build/G2MJ01/ok \r\n\
             dtk.exe shasum  -c config\\G2MJ01\\build.sha1 -o build\\G2MJ01\\ok\r\n\
             build/G2MJ01/main.dol: FAILED\n\
             WARNING: 1 computed checksum(s) did NOT match\n\
             ninja: build stopped: subcommand failed.",
        );
        assert_eq!(kind, Kind::RetailMismatch);
        assert!(linker.is_empty());
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
