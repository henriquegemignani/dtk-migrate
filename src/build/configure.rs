//! Running the project's own `configure.py`, then making its build graph safe
//! for trials.
//!
//! Two rules in the generated `build.ninja` need changing, and neither change
//! belongs in the project's sources:
//!
//! - **split** must not update the project's own `splits.txt` and `symbols.txt`
//!   as a side effect of building. A trial is supposed to be reversible, and a
//!   splitter that rewrites its inputs is not. It also needs a bounded `-j`, so
//!   one worker's dtk does not take the machine.
//! - **configure** regenerates `build.ninja` whenever an input changes, which
//!   would undo the first change halfway through a build. Pointing it at this
//!   binary instead means the patch survives regeneration.
//!
//! The Python this replaces monkeypatched the project's Ninja writer from
//! inside the configure process. Rewriting the generated file afterwards does
//! the same job without needing to be Python.

use std::path::Path;

use anyhow::{Context, Result, bail};

/// The `dtk dol split` flags a trial needs.
const SPLIT_MARKER: &str = " dol split ";

/// Rewrites a generated `build.ninja` so trials are reversible and bounded.
///
/// `hook` is the command that should run in place of the project's own
/// configure invocation — this binary, which will run it and then apply this
/// same patch to the file it produces.
///
/// Idempotent: a file that already carries the patch comes back unchanged.
pub fn patch_build_ninja(text: &str, jobs: usize, hook: &str) -> Result<String> {
    if jobs == 0 {
        bail!("Build jobs must be positive");
    }
    let mut out: Vec<String> = Vec::new();
    let mut rule: Option<String> = None;
    let mut patched_split = false;
    let mut patched_configure = false;

    for (logical, original) in fold_continuations(text) {
        let body = logical.strip_suffix('\n').unwrap_or(&logical);
        if let Some(name) = body.strip_prefix("rule ") {
            rule = Some(name.trim().to_string());
            out.push(original);
            continue;
        }
        // Any line that is not indented ends the rule block.
        if !body.starts_with(' ') && !body.trim().is_empty() {
            rule = None;
        }
        let Some(command) = body.strip_prefix("  command = ") else {
            out.push(original);
            continue;
        };
        match rule.as_deref() {
            Some("split") => {
                if command.contains("--no-update") {
                    patched_split = true;
                    out.push(original);
                    continue;
                }
                let Some(index) = command.find(SPLIT_MARKER) else {
                    bail!("Unsupported dtk-template split rule: {command}");
                };
                let (before, after) = command.split_at(index + SPLIT_MARKER.len());
                out.push(format!("  command = {before}--no-update -j {jobs} {after}\n"));
                patched_split = true;
            }
            Some("configure") => {
                if command.starts_with(&escape(hook)) {
                    patched_configure = true;
                    out.push(original);
                    continue;
                }
                if !command.contains("$python") || !command.contains("$configure_args") {
                    bail!("Unsupported dtk-template configure rule: {command}");
                }
                out.push(format!(
                    "  command = {} configure-hook --jobs {jobs} -- {command}\n",
                    escape(hook)
                ));
                patched_configure = true;
            }
            _ => out.push(original),
        }
    }

    if !patched_split {
        bail!("No split rule found in build.ninja");
    }
    if !patched_configure {
        bail!("No configure rule found in build.ninja");
    }
    Ok(out.concat())
}

/// Joins Ninja's `$`-continued lines, keeping the original text alongside.
///
/// dtk-template's writer wraps anything past 78 columns, and a run's frozen dtk
/// sits under a long path, so the split rule's command arrives in three pieces.
/// Matching against a fragment finds nothing.
///
/// Each entry is `(logical line, original text)`. A line this function does not
/// change is emitted from its original text, so the file only differs where it
/// was deliberately patched.
fn fold_continuations(text: &str) -> Vec<(String, String)> {
    let mut folded: Vec<(String, String)> = Vec::new();
    let mut logical = String::new();
    let mut original = String::new();
    for line in text.split_inclusive('\n') {
        original.push_str(line);
        let body = line.strip_suffix('\n').unwrap_or(line).trim_end_matches('\r');
        // A trailing `$` continues the line; `$$` is an escaped dollar, so only
        // an odd number of them counts.
        let dollars = body.len() - body.trim_end_matches('$').len();
        if dollars % 2 == 1 {
            // The writer splits at a space and re-indents the continuation, so
            // one space rejoins them.
            let part = body[..body.len() - 1].trim_end();
            if logical.is_empty() {
                logical.push_str(part);
            } else {
                logical.push(' ');
                logical.push_str(part.trim_start());
            }
            continue;
        }
        if logical.is_empty() {
            logical.push_str(body);
        } else {
            logical.push(' ');
            logical.push_str(body.trim_start());
        }
        logical.push('\n');
        folded.push((std::mem::take(&mut logical), std::mem::take(&mut original)));
    }
    if !original.is_empty() {
        folded.push((logical, original));
    }
    folded
}

/// Quotes a path for a Ninja command line.
///
/// `$` is Ninja's own escape character, so a path containing one has to be
/// doubled or the command silently loses part of itself.
fn escape(path: &str) -> String { format!("\"{}\"", path.replace('$', "$$")) }

/// Applies [`patch_build_ninja`] to the file in `root`.
pub fn patch_in_place(root: &Path, jobs: usize, hook: &str) -> Result<()> {
    let path = root.join("build.ninja");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let patched = patch_build_ninja(&text, jobs, hook)
        .with_context(|| format!("While patching {}", path.display()))?;
    if patched != text {
        std::fs::write(&path, patched)
            .with_context(|| format!("Failed to write {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NINJA: &str = "configure_args = --map --version PAL\n\
                         python = \"C:\\python.exe\"\n\
                         \n\
                         rule split\n  \
                           command = build\\tools\\dtk.exe dol split $in $out_dir\n  \
                           description = SPLIT $in\n\
                         \n\
                         rule configure\n  \
                           command = $python configure.py $configure_args\n  \
                           generator = 1\n\
                         \n\
                         rule progress\n  \
                           command = $python configure.py $configure_args progress\n";

    #[test]
    fn the_split_rule_gains_no_update_and_a_job_bound() {
        let out = patch_build_ninja(NINJA, 4, "dtk-migrate.exe").unwrap();
        assert!(
            out.contains("dol split --no-update -j 4 $in $out_dir"),
            "{}",
            out.lines().find(|l| l.contains("dol split")).unwrap()
        );
    }

    #[test]
    fn the_configure_rule_runs_through_the_hook() {
        let out = patch_build_ninja(NINJA, 4, "dtk-migrate.exe").unwrap();
        assert!(
            out.contains(
                "command = \"dtk-migrate.exe\" configure-hook --jobs 4 -- $python configure.py $configure_args\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn the_progress_rule_is_left_alone() {
        let out = patch_build_ninja(NINJA, 4, "dtk-migrate.exe").unwrap();
        assert!(
            out.contains("  command = $python configure.py $configure_args progress\n"),
            "{out}"
        );
    }

    #[test]
    fn patching_twice_changes_nothing_the_second_time() {
        let once = patch_build_ninja(NINJA, 4, "dtk-migrate.exe").unwrap();
        let twice = patch_build_ninja(&once, 4, "dtk-migrate.exe").unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn a_dollar_in_the_hook_path_is_escaped_for_ninja() {
        let out = patch_build_ninja(NINJA, 1, "C:\\a$b\\dtk-migrate.exe").unwrap();
        assert!(out.contains("\"C:\\a$$b\\dtk-migrate.exe\""), "{out}");
    }

    #[test]
    fn a_split_rule_that_is_not_dol_split_is_refused() {
        let text = NINJA.replace("dol split", "rel split");
        assert!(patch_build_ninja(&text, 4, "x").unwrap_err().to_string().contains("Unsupported"));
    }

    #[test]
    fn a_configure_rule_without_the_expected_variables_is_refused() {
        let text =
            NINJA.replace("command = $python configure.py $configure_args\n", "command = make\n");
        assert!(patch_build_ninja(&text, 4, "x").unwrap_err().to_string().contains("Unsupported"));
    }

    #[test]
    fn a_missing_rule_is_an_error_rather_than_a_silent_pass() {
        let text = NINJA.replace("rule configure\n", "rule other\n");
        assert!(
            patch_build_ninja(&text, 4, "x").unwrap_err().to_string().contains("configure rule")
        );
    }

    #[test]
    fn zero_jobs_is_refused() {
        assert!(patch_build_ninja(NINJA, 0, "x").is_err());
    }

    #[test]
    fn a_wrapped_command_is_joined_and_patched() {
        // dtk-template wraps past 78 columns, and a run's frozen dtk sits under
        // a long path, so this is the shape the real file arrives in.
        let text = NINJA.replace(
            "  command = build\\tools\\dtk.exe dol split $in $out_dir\n",
            "  command = $\n      C:\\very\\long\\path\\dtk.exe $\n      dol split $in $out_dir\n",
        );
        let out = patch_build_ninja(&text, 4, "dtk-migrate.exe").unwrap();
        assert!(
            out.contains(
                "  command = C:\\very\\long\\path\\dtk.exe dol split --no-update -j 4 $in $out_dir\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn a_wrapped_line_this_does_not_patch_is_left_exactly_as_it_was() {
        let wrapped = "build a b: link $\n    one $\n    two\n";
        let text = format!("{NINJA}{wrapped}");
        let out = patch_build_ninja(&text, 4, "x").unwrap();
        assert!(out.ends_with(wrapped), "{out}");
    }

    #[test]
    fn an_escaped_dollar_at_the_end_is_not_a_continuation() {
        let text = format!("{NINJA}value = costs $$\nnext = 1\n");
        let out = patch_build_ninja(&text, 4, "x").unwrap();
        assert!(out.contains("value = costs $$\nnext = 1\n"), "{out}");
    }

    #[test]
    fn patching_a_wrapped_file_twice_changes_nothing_the_second_time() {
        let text = NINJA.replace(
            "  command = build\\tools\\dtk.exe dol split $in $out_dir\n",
            "  command = $\n      C:\\very\\long\\path\\dtk.exe $\n      dol split $in $out_dir\n",
        );
        let once = patch_build_ninja(&text, 4, "dtk-migrate.exe").unwrap();
        assert_eq!(once, patch_build_ninja(&once, 4, "dtk-migrate.exe").unwrap());
    }
}
