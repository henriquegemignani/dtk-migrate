//! Enabling whole source files, once their compiled objects are shown to link
//! and produce retail bytes.
//!
//! This is the only stage whose acceptance means "this file's source is
//! correct". The others move boundaries and names around, which improves what a
//! comparison can see without ever compiling the candidate into the shipped
//! binary.
//!
//! What makes it a proof and not a coincidence is that both halves are checked.
//! A retail hash on its own proves nothing here: `tools/project.py` links the
//! *extracted original* object for any file `configure.py` has not enabled, so
//! a build can pass its checksum while the candidate's source was never
//! compiled into it. That is the circularity the earlier tool fell into. So
//! every accepted unit must also appear, by its compiled object path, in the
//! actual Ninja input list of the artifact it belongs to.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};

use crate::{
    build::context::{BuildContext, ValidationError},
    project::{
        configure_py::Configure,
        report::{ObjdiffConfig, ObjdiffUnit, Report, strip_source_root},
        transaction::Owned,
    },
    stages::{Candidate, Event, Outcome, Prepared, Selections, Stage, bisect},
};

pub struct Verify;

/// What acceptance in this stage establishes.
const VALIDATION: &str = "compiled-link-inputs-and-retail-bytes";

impl Stage for Verify {
    fn name(&self) -> &'static str { "verify" }

    fn prepare(&self, ctx: &BuildContext, limit: Option<usize>) -> Result<Prepared> {
        if limit == Some(0) {
            bail!("limit must be positive");
        }
        let path = ctx.root.join("configure.py");
        let mut owned = Owned::take(&path)?;
        let text = String::from_utf8(owned.original().to_vec())?;
        let configure = Configure::parse(&text)?;

        // Fold any legacy override block into ordinary statuses before
        // measuring, so the baseline reflects what the project really enables.
        let migrated: BTreeMap<String, Vec<String>> = configure
            .legacy_blocks()
            .iter()
            .map(|block| (block.version.clone(), block.names.iter().cloned().collect()))
            .collect();
        let rendered = configure.render(&ctx.target, &BTreeSet::new())?;
        owned.write(rendered.as_bytes())?;

        let migrated_configure = Configure::parse(&rendered)?;
        let mut unsplit = Vec::new();
        let baseline = validate(
            ctx,
            &migrated_configure.configured_names(&ctx.target),
            false,
            Some(&mut unsplit),
        )?;
        owned.check()?;

        let units = baseline.by_source_name();
        let mut candidates: Vec<(&str, u64)> = units
            .iter()
            .filter(|(_, unit)| unit.metadata.complete != Some(true))
            .filter(|(_, unit)| unit.matched_code() > 0)
            .filter(|(_, unit)| unit.matches_on_content())
            .map(|(name, unit)| (*name, unit.matched_code()))
            .collect();
        // Biggest first: the most matched code per build, and a batch that fails
        // costs less to bisect when its members are not interchangeable.
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));

        // Candidates come from the build report, which says nothing about how an
        // object is declared. Dropping the ones whose declaration cannot be
        // rewritten costs those units; leaving them in costs whichever batch
        // they land in, after that batch has already done its builds.
        let blocked = migrated_configure.unrewritable_names();
        let mut events: Vec<Event> = candidates
            .iter()
            .filter_map(|(name, _)| blocked.get(*name).map(|kind| (name, kind)))
            .map(|(name, kind)| {
                Event::new(*name, "skipped").because(format!("{kind} cannot be widened safely"))
            })
            .collect();
        events.extend(unsplit.iter().map(|name| {
            Event::new(name, "configured-without-split").because(format!(
                "MatchingFor({0}) but {0} has no split for it, so nothing is compiled or linked",
                ctx.target
            ))
        }));

        let mut chosen: Vec<Candidate> = candidates
            .into_iter()
            .filter(|(name, _)| !blocked.contains_key(*name))
            .map(|(name, _)| Candidate::new(name))
            .collect();
        if let Some(limit) = limit {
            chosen.truncate(limit);
        }

        let mut extra = serde_json::Map::new();
        extra.insert("migrated_legacy".into(), serde_json::to_value(&migrated)?);
        // The rendered configuration is the baseline every trial renders from.
        owned.commit();
        Ok(Prepared { candidates: chosen, baseline, events, extra, permitted: Default::default() })
    }

    fn evaluate(
        &self,
        ctx: &BuildContext,
        _prepared: &Prepared,
        candidates: &[Candidate],
        _preferred: &Selections,
    ) -> Result<Outcome> {
        let path = ctx.root.join("configure.py");
        let mut owned = Owned::take(&path)?;
        let text = String::from_utf8(owned.original().to_vec())?;
        let configure = Configure::parse(&text)?;

        // Preflight before writing anything: a name this file cannot express
        // should fail now, not after the batch has done its builds.
        let requested: BTreeSet<String> = candidates.iter().map(|c| c.name.clone()).collect();
        configure.render(&ctx.target, &requested)?;
        let baseline_names = configure.configured_names(&ctx.target);

        let write = |owned: &mut Owned, names: &BTreeSet<String>| -> Result<()> {
            owned.write(configure.render(&ctx.target, names)?.as_bytes())
        };

        let (accepted, deferred, events) = bisect(
            candidates,
            "failed-source-link-or-hash",
            "retail-hash-verified-source",
            |already, batch| {
                let proposed: BTreeSet<String> =
                    already.iter().chain(batch).map(|c| c.name.clone()).collect();
                write(&mut owned, &proposed)?;
                let mut checked = baseline_names.clone();
                checked.extend(proposed.iter().cloned());
                match validate(ctx, &checked, true, None) {
                    Ok(_) => Ok(()),
                    Err(error) => {
                        // Put the file back to the accepted set before the next
                        // trial, so a failure never leaks into the one after it.
                        let kept: BTreeSet<String> =
                            already.iter().map(|c| c.name.clone()).collect();
                        write(&mut owned, &kept)?;
                        Err(error)
                    }
                }
            },
        )?;

        let kept: BTreeSet<String> = accepted.iter().map(|c| c.name.clone()).collect();
        write(&mut owned, &kept)?;
        let mut checked = baseline_names;
        checked.extend(kept);
        let report = validate(ctx, &checked, false, None)?;
        owned.check()?;
        owned.commit();
        Ok(Outcome {
            tried: Default::default(),
            accepted,
            deferred,
            events,
            report,
            validation: VALIDATION.to_string(),
            selections: Selections::new(),
        })
    }

    fn validate(
        &self,
        ctx: &BuildContext,
        accepted: &[Candidate],
        _prepared: &Prepared,
        _selections: &Selections,
    ) -> Result<Report> {
        let text = std::fs::read_to_string(ctx.root.join("configure.py"))?;
        let mut names = Configure::parse(&text)?.configured_names(&ctx.target);
        names.extend(accepted.iter().map(|c| c.name.clone()));
        validate(ctx, &names, false, None)
    }
}

/// Builds, then requires every named unit to be a real input to a real link.
///
/// `record`, when given, collects configured units this version has no split
/// for. Such a unit is declared `MatchingFor(<target>)` but appears in neither
/// the report nor `objdiff.json`, because dtk emits no rule for a unit it cannot
/// place — so nothing is compiled and nothing is linked. That is vacuous rather
/// than wrong (the units it happens to are empty ones, whose split in the source
/// version is a zero-length range), and it is a standing property of the
/// configuration rather than anything a candidate did. Failing the whole stage
/// on it would block work that has nothing to do with it.
pub fn validate(
    ctx: &BuildContext,
    names: &BTreeSet<String>,
    trial: bool,
    mut record: Option<&mut Vec<String>>,
) -> Result<Report> {
    let report = if trial { ctx.trial_build()? } else { ctx.build(None)? };
    let units = report.by_source_name();

    let objdiff = ObjdiffConfig::read(&ctx.root.join("objdiff.json"))?;
    let mut comparison: BTreeMap<&str, &ObjdiffUnit> = BTreeMap::new();
    for unit in &objdiff.units {
        let Some(source) = unit.metadata.source_path.as_deref() else { continue };
        let name = strip_source_root(source);
        if !names.contains(name) {
            continue;
        }
        if comparison.insert(name, unit).is_some() {
            bail!(ValidationError(format!("Ambiguous objdiff source unit: {name}")));
        }
    }

    let mut linked: BTreeMap<Option<String>, BTreeSet<String>> = BTreeMap::new();
    for name in names {
        let unit = comparison.get(name.as_str()).copied();
        if unit.is_none() && !units.contains_key(name.as_str()) {
            // No split for this version, so there is no object and no link to
            // check. Anything with a split reaches the checks below.
            if let Some(record) = record.as_mut() {
                record.push(name.clone());
            }
            continue;
        }
        let target_path = unit.and_then(|u| u.target_path.as_deref()).unwrap_or_default();
        let module = module_of(target_path, &ctx.target);

        // dtk's report covers the DOL; a REL's units are absent from it
        // entirely, so their completeness is a question it cannot answer. The
        // link check below is the half that actually tests "configured to link
        // from source", and it works for every module.
        if module.is_none()
            && units.get(name.as_str()).and_then(|u| u.metadata.complete) != Some(true)
        {
            bail!(ValidationError(format!("{name} was not configured to link from source")));
        }

        if !linked.contains_key(&module) {
            linked.insert(module.clone(), link_inputs(ctx, module.as_deref())?);
        }
        let object = unit.and_then(|u| u.base_path.as_deref()).unwrap_or_default();
        let artifact = match &module {
            None => "main.elf".to_string(),
            Some(module) => format!("{module}.plf"),
        };
        if object.is_empty() || !linked[&module].contains(&normalize(ctx, object)) {
            bail!(ValidationError(format!(
                "{name}'s compiled object is not an input to {artifact}"
            )));
        }
    }
    Ok(report)
}

/// The objects a module's link actually consumes, as Ninja reports them.
fn link_inputs(ctx: &BuildContext, module: Option<&str>) -> Result<BTreeSet<String>> {
    let artifact = match module {
        None => format!("build/{}/main.elf", ctx.target),
        Some(module) => format!("build/{}/{module}/{module}.plf", ctx.target),
    };
    let args = vec!["-t".to_string(), "inputs".to_string(), artifact.clone()];
    let output = ctx
        .run(&ctx.tools.ninja.clone(), &args, true, None)
        .map_err(anyhow::Error::new)
        .with_context(|| format!("Failed to list the inputs of {artifact}"))?;
    Ok(output.lines().filter(|line| !line.trim().is_empty()).map(|p| normalize(ctx, p)).collect())
}

/// One spelling for a path, so a Ninja listing and an objdiff entry compare.
fn normalize(ctx: &BuildContext, path: &str) -> String {
    let joined = ctx.root.join(path.replace('\\', "/"));
    let text = joined.to_string_lossy().replace('\\', "/");
    // Collapse the `a/./b` and `a/b/../c` forms Ninja and objdiff each produce
    // in their own way, then case-fold where the filesystem does.
    let mut parts: Vec<&str> = Vec::new();
    for part in text.split('/') {
        match part {
            "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if cfg!(windows) { joined.to_lowercase() } else { joined }
}

/// The REL module a compiled object belongs to, or `None` for the DOL.
///
/// dtk puts a module's extracted objects under `build/<version>/<module>/obj/`
/// and the DOL's directly under `build/<version>/obj/`, so the path says which
/// link an object is destined for. A unit configured with
/// `MatchingFor(<version>)` may live in either, and the two are validated
/// against different artifacts.
pub fn module_of(target_path: &str, version: &str) -> Option<String> {
    let normalized = target_path.replace('\\', "/");
    let parts: Vec<&str> = normalized.split('/').filter(|p| !p.is_empty()).collect();
    let index = parts.iter().position(|part| *part == version)?;
    let after = &parts[index + 1..];
    match after {
        [first, _rest @ ..] if after.len() > 1 && *first != "obj" => Some((*first).to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_object_under_the_version_root_belongs_to_the_dol() {
        assert_eq!(module_of("build/GM8P01_00/obj/MetroidPrime/main.o", "GM8P01_00"), None);
    }

    #[test]
    fn an_object_under_a_module_directory_names_that_module() {
        assert_eq!(
            module_of("build/GM8P01_00/NESPALemuP/obj/NESemu/emu.o", "GM8P01_00"),
            Some("NESPALemuP".to_string())
        );
    }

    #[test]
    fn a_windows_path_reads_the_same_as_a_posix_one() {
        assert_eq!(
            module_of("build\\GM8P01_00\\NESPALemuP\\obj\\emu.o", "GM8P01_00"),
            Some("NESPALemuP".to_string())
        );
    }

    #[test]
    fn a_path_that_does_not_mention_the_version_has_no_module() {
        assert_eq!(module_of("build/GM8E01_00/obj/main.o", "GM8P01_00"), None);
        assert_eq!(module_of("", "GM8P01_00"), None);
    }

    #[test]
    fn a_bare_version_directory_has_no_module() {
        assert_eq!(module_of("build/GM8P01_00/main.dol", "GM8P01_00"), None);
    }
}
