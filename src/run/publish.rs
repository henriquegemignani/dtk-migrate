//! Moving a proven result into the user's own checkout.
//!
//! This is the only code that writes there, and it is written on the assumption
//! that the checkout is someone's working copy rather than a scratch directory.
//! So:
//!
//! - only four files may change, and any other difference stops publication;
//! - the checkout must be byte-for-byte what the run measured, or the result
//!   describes a project that no longer exists;
//! - every replacement is journalled before it happens, so an interrupted
//!   publication can be recognised and undone;
//! - the gate is re-run *there*, because a worker proved something in a copy;
//! - and a rollback never overwrites an edit made meanwhile. Someone else's
//!   work outranks undoing ours.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    project::{report::Report, splits::Splits},
    run::{RunDir, RunRecord, StageResult, context, read_json, stage_for, write_json},
    stages::{FinalCertificates, Prepared, coverage::AppliedRecord, discover},
    workspace::{Manifest, Snapshot},
};

/// The only files a migration may change in the user's project.
pub fn publishable(target: &str) -> BTreeSet<String> {
    BTreeSet::from([
        "configure.py".to_string(),
        format!("config/{target}/config.yml"),
        format!("config/{target}/splits.txt"),
        format!("config/{target}/symbols.txt"),
    ])
}

/// What publication is about to do, or did, written before the first write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Journal {
    pub status: Status,
    pub changes: BTreeMap<String, Change>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    /// Digest of the final composed ownership and certificate graph.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_certificates_sha256: Option<String>,
}

/// The complete final body of every certified unit and the evidence chain
/// that led to it. The stage results retain the detailed proposals; this
/// index makes the composed final state and its cross-unit dependencies
/// explicit for publication and resume audits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateGraph {
    pub schema: u32,
    pub target: String,
    pub splits_sha256: Option<String>,
    pub units: BTreeMap<String, UnitCertificate>,
    pub dependencies: Vec<CertificateDependency>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UnitCertificate {
    pub body: Option<Vec<String>>,
    pub coverage_transactions: Vec<String>,
    pub discovery: Option<DiscoveryCertificate>,
    pub verified_source_link: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryCertificate {
    pub kind: discover::Kind,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDependency {
    pub transaction: String,
    pub reads: String,
    pub sections: Vec<String>,
}

fn certificate_graph(
    root: &Path,
    target: &str,
    results: &BTreeMap<String, (StageResult, Prepared)>,
    certificates: &FinalCertificates,
) -> Result<CertificateGraph> {
    let splits_path = root.join("config").join(target).join("splits.txt");
    let splits = read_optional(&splits_path)?;
    let blocks = match &splits {
        Some(bytes) => Splits::parse(&String::from_utf8(bytes.clone())?)?.blocks,
        None => Default::default(),
    };
    let mut units: BTreeMap<String, UnitCertificate> = BTreeMap::new();
    let mut dependencies = Vec::new();
    if let Some((coverage, _)) = results.get("coverage") {
        for applied in &coverage.applied {
            let record: AppliedRecord = serde_json::from_value(applied.record.clone())?;
            let transaction = &record.alternative.transaction;
            if transaction.id != applied.id {
                bail!("Final certificate transaction differs from applied history");
            }
            let sections: Vec<String> =
                crate::stages::coverage::changed_sections(transaction).into_iter().collect();
            for member in &transaction.members {
                units
                    .entry(member.unit.clone())
                    .or_default()
                    .coverage_transactions
                    .push(transaction.id.clone());
            }
            for read in &transaction.reads {
                dependencies.push(CertificateDependency {
                    transaction: transaction.id.clone(),
                    reads: read.unit.clone(),
                    sections: sections.clone(),
                });
            }
        }
    }
    if let Some((discovery, _)) = results.get("discover") {
        for candidate in &discovery.accepted {
            let proposal: discover::Proposal = serde_json::from_value(candidate.evidence.clone())?;
            units.entry(candidate.name.clone()).or_default().discovery =
                Some(DiscoveryCertificate {
                    kind: proposal.kind,
                    evidence_sha256: hash_file_bytes(&serde_json::to_vec(&candidate.evidence)?),
                });
        }
    }
    for name in &certificates.source_linked {
        units.entry(name.clone()).or_default().verified_source_link = true;
    }
    for (name, certificate) in &mut units {
        certificate.body = blocks.get(name).cloned();
        if certificate.body.is_none()
            && (!certificate.coverage_transactions.is_empty() || certificate.discovery.is_some())
        {
            bail!("Final ownership certificate for {name} has no split body");
        }
    }
    Ok(CertificateGraph {
        schema: 1,
        target: target.to_string(),
        splits_sha256: splits.as_deref().map(hash_file_bytes),
        units,
        dependencies,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Publishing,
    Published,
    RolledBack,
    /// Rolled back, except where the user had edited the file meanwhile.
    UserEditConflict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
    /// The bytes themselves, so a rollback works even if the run directory is
    /// all that survives a crash.
    pub before: Option<String>,
    pub after: Option<String>,
}

fn encode(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn decode(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        bail!("Journal entry is not valid hex");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).context("Journal entry is not valid hex"))
        .collect()
}

/// Publishes the integrated workspace into the owner project.
pub fn publish(
    root: &Path,
    integrated: &Path,
    dir: &RunDir,
    run: &RunRecord,
    results: &BTreeMap<String, (StageResult, Prepared)>,
) -> Result<Report> {
    crate::run::check_environment(run)?;

    let owner = Snapshot::of(root)?;
    if owner.manifest != run.owner.manifest || owner.mappings != run.owner.mappings {
        bail!(
            "The project changed while this run was working. Nothing was published; \
             the evidence is retained so it can be revalidated against the new state."
        );
    }
    let final_manifest = Snapshot::of(integrated)?.manifest;

    let changed: BTreeSet<String> = owner
        .manifest
        .keys()
        .chain(final_manifest.keys())
        .filter(|name| owner.manifest.get(*name) != final_manifest.get(*name))
        .cloned()
        .collect();
    let allowed = publishable(&run.target);
    let unexpected: Vec<&String> = changed.difference(&allowed).collect();
    if !unexpected.is_empty() {
        bail!("Integration changed files a migration may not publish: {unexpected:?}");
    }

    let mut journal = Journal {
        status: Status::Publishing,
        changes: BTreeMap::new(),
        conflicts: Vec::new(),
        final_certificates_sha256: None,
    };
    for name in &changed {
        journal.changes.insert(name.clone(), Change {
            before_sha256: owner.manifest.get(name).cloned(),
            after_sha256: final_manifest.get(name).cloned(),
            before: read_optional(&root.join(name))?.map(|b| encode(&b)),
            after: read_optional(&integrated.join(name))?.map(|b| encode(&b)),
        });
    }
    let journal_path = dir.path.join("publication.json");
    write_json(&journal_path, &journal)?;

    let ctx = context(root, run, dir.path.join("owner-validation"), None);
    let outcome = (|| -> Result<(Report, String)> {
        for (name, change) in &journal.changes {
            let path = root.join(name);
            if read_optional(&path)?.map(|b| hash_file_bytes(&b)) != change.before_sha256 {
                bail!("{name} changed during publication");
            }
            match &change.after {
                Some(after) => replace(&path, &decode(after)?)?,
                None => std::fs::remove_file(&path).ok().map(|_| ()).unwrap_or(()),
            }
        }

        // Prove it again here. The worker proved it in a copy; this is the
        // project that will keep it.
        let mut report = ctx.build(None)?;
        let mut certificates = FinalCertificates::default();
        // A source-link proof is a fact about the *final* graph. Establish it
        // first, then coverage can stop requiring the older extracted-input
        // condition for exactly those units while still replaying ownership.
        if run.stages.iter().any(|name| name == "verify")
            && let Some((result, prepared)) = results.get("verify")
            && (!result.accepted.is_empty() || !result.applied.is_empty())
        {
            report = stage_for("verify")?.validate(
                &ctx,
                &result.accepted,
                prepared,
                &result.selections,
                &result.applied,
            )?;
            certificates.source_linked.extend(result.accepted.iter().map(|c| c.name.clone()));
        }
        for stage_name in &run.stages {
            if stage_name == "verify" {
                continue;
            }
            let Some((result, prepared)) = results.get(stage_name) else { continue };
            if result.accepted.is_empty() && result.applied.is_empty() {
                continue;
            }
            report = stage_for(stage_name)?.validate_final(
                &ctx,
                &result.accepted,
                prepared,
                &result.selections,
                &result.applied,
                &certificates,
            )?;
        }
        crate::run::check_environment(run)?;
        let after = Snapshot::of(root)?;
        if after.manifest != final_manifest || after.mappings != Snapshot::of(integrated)?.mappings
        {
            bail!("The project changed during final validation");
        }
        ctx.restore_generated_graph()?;
        let graph = certificate_graph(root, &run.target, results, &certificates)?;
        let path = dir.path.join("final-certificates.json");
        write_json(&path, &graph)?;
        Ok((report, hash_file_bytes(&std::fs::read(path)?)))
    })();

    match outcome {
        Ok((report, certificate_sha256)) => {
            journal.final_certificates_sha256 = Some(certificate_sha256);
            journal.status = Status::Published;
            write_json(&journal_path, &journal)?;
            Ok(report)
        }
        Err(error) => {
            let _ = std::fs::remove_file(dir.path.join("final-certificates.json"));
            journal.conflicts = roll_back(root, &journal)?;
            journal.status = if journal.conflicts.is_empty() {
                Status::RolledBack
            } else {
                Status::UserEditConflict
            };
            write_json(&journal_path, &journal)?;
            if journal.conflicts.is_empty() && Snapshot::of(root)?.manifest == owner.manifest {
                // Leave the project buildable, but never let a failure here
                // mask the failure that caused the rollback.
                if let Err(rebuild) = ctx.build(None) {
                    tracing::error!(
                        "The project was restored, but rebuilding its report failed: {rebuild:#}"
                    );
                }
                if let Err(restore) = ctx.restore_generated_graph() {
                    tracing::error!(
                        "The project inputs were restored, but its ordinary build graph was not: \
                         {restore:#}"
                    );
                }
            }
            Err(error)
        }
    }
}

/// Puts back everything the journal replaced, except where someone has edited
/// it since.
pub fn roll_back(root: &Path, journal: &Journal) -> Result<Vec<String>> {
    let mut conflicts = Vec::new();
    for (name, change) in &journal.changes {
        let path = root.join(name);
        let current = read_optional(&path)?;
        let current_hash = current.as_deref().map(hash_file_bytes);
        if current_hash == change.before_sha256 {
            continue; // Already as it was.
        }
        if current_hash != change.after_sha256 {
            // Someone edited it after we wrote. Their work outranks our undo.
            conflicts.push(name.clone());
            continue;
        }
        match &change.before {
            Some(before) => replace(&path, &decode(before)?)?,
            None => {
                std::fs::remove_file(&path).ok();
            }
        }
    }
    Ok(conflicts)
}

/// Finishes or undoes a publication an earlier run left in progress.
pub fn recover(root: &Path, dir: &RunDir) -> Result<Option<Status>> {
    let journal_path = dir.path.join("publication.json");
    if !journal_path.exists() {
        return Ok(None);
    }
    let mut journal: Journal = read_json(&journal_path)?;
    if journal.status != Status::Publishing {
        if journal.status == Status::Published {
            let expected = journal
                .final_certificates_sha256
                .as_ref()
                .context("Published run has no final certificate graph digest")?;
            let path = dir.path.join("final-certificates.json");
            if hash_file_bytes(&std::fs::read(&path)?) != *expected {
                bail!("Final certificate graph changed since publication");
            }
        }
        return Ok(Some(journal.status));
    }
    journal.conflicts = roll_back(root, &journal)?;
    journal.status =
        if journal.conflicts.is_empty() { Status::RolledBack } else { Status::UserEditConflict };
    let _ = std::fs::remove_file(dir.path.join("final-certificates.json"));
    write_json(&journal_path, &journal)?;
    Ok(Some(journal.status))
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
    }
}

fn hash_file_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Writes through a temporary file in the same directory, so a reader never
/// sees a partial file and a crash leaves either the old one or the new one.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let directory = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(directory)?;
    let mut temporary = tempfile::Builder::new().prefix(".publish.").tempfile_in(directory)?;
    use std::io::Write;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// Every file the owner project currently holds, for a caller that wants to
/// compare before publishing.
pub fn owner_manifest(root: &Path) -> Result<Manifest> { crate::workspace::snapshot_manifest(root) }

/// The run directory for one identifier, rejecting anything that is not one.
pub fn run_directory(root: &Path, id: &str) -> Result<PathBuf> {
    let valid = !id.is_empty()
        && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        && id != "."
        && id != "..";
    if !valid {
        bail!("A run id may only contain letters, digits, '.', '-' and '_': {id}");
    }
    Ok(runs_root(root).join(id))
}

pub fn runs_root(root: &Path) -> PathBuf { root.join("build").join("dtk-migrate").join("runs") }

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("config/PAL")).unwrap();
        std::fs::write(dir.path().join("configure.py"), "original\n").unwrap();
        dir
    }

    fn journal(root: &Path, after: &str) -> Journal {
        let before = std::fs::read(root.join("configure.py")).unwrap();
        Journal {
            status: Status::Publishing,
            changes: BTreeMap::from([("configure.py".to_string(), Change {
                before_sha256: Some(hash_file_bytes(&before)),
                after_sha256: Some(hash_file_bytes(after.as_bytes())),
                before: Some(encode(&before)),
                after: Some(encode(after.as_bytes())),
            })]),
            conflicts: Vec::new(),
            final_certificates_sha256: None,
        }
    }

    #[test]
    fn only_the_four_migration_files_may_be_published() {
        let allowed = publishable("PAL");
        assert!(allowed.contains("configure.py"));
        assert!(allowed.contains("config/PAL/splits.txt"));
        assert!(!allowed.contains("src/main.cpp"));
        assert_eq!(allowed.len(), 4);
    }

    #[test]
    fn a_rollback_restores_what_publication_wrote() {
        let dir = project();
        let journal = journal(dir.path(), "published\n");
        std::fs::write(dir.path().join("configure.py"), "published\n").unwrap();
        let conflicts = roll_back(dir.path(), &journal).unwrap();
        assert!(conflicts.is_empty());
        assert_eq!(std::fs::read_to_string(dir.path().join("configure.py")).unwrap(), "original\n");
    }

    #[test]
    fn a_rollback_leaves_an_intervening_edit_alone_and_names_it() {
        let dir = project();
        let journal = journal(dir.path(), "published\n");
        std::fs::write(dir.path().join("configure.py"), "published\n").unwrap();
        std::fs::write(dir.path().join("configure.py"), "their own edit\n").unwrap();
        let conflicts = roll_back(dir.path(), &journal).unwrap();
        assert_eq!(conflicts, ["configure.py"]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("configure.py")).unwrap(),
            "their own edit\n"
        );
    }

    #[test]
    fn a_rollback_of_something_never_written_does_nothing() {
        let dir = project();
        let journal = journal(dir.path(), "published\n");
        assert!(roll_back(dir.path(), &journal).unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(dir.path().join("configure.py")).unwrap(), "original\n");
    }

    #[test]
    fn recovering_an_interrupted_publication_undoes_it() {
        let dir = project();
        let run = RunDir { path: dir.path().join("run") };
        let journal = journal(dir.path(), "published\n");
        std::fs::write(dir.path().join("configure.py"), "published\n").unwrap();
        write_json(&run.path.join("publication.json"), &journal).unwrap();
        std::fs::write(run.path.join("final-certificates.json"), b"incomplete").unwrap();
        assert_eq!(recover(dir.path(), &run).unwrap(), Some(Status::RolledBack));
        assert_eq!(std::fs::read_to_string(dir.path().join("configure.py")).unwrap(), "original\n");
        assert!(!run.path.join("final-certificates.json").exists());
    }

    #[test]
    fn recovering_a_finished_publication_changes_nothing() {
        let dir = project();
        let run = RunDir { path: dir.path().join("run") };
        let mut journal = journal(dir.path(), "published\n");
        journal.status = Status::Published;
        std::fs::create_dir_all(&run.path).unwrap();
        std::fs::write(run.path.join("final-certificates.json"), b"certificate").unwrap();
        journal.final_certificates_sha256 = Some(hash_file_bytes(b"certificate"));
        std::fs::write(dir.path().join("configure.py"), "published\n").unwrap();
        write_json(&run.path.join("publication.json"), &journal).unwrap();
        assert_eq!(recover(dir.path(), &run).unwrap(), Some(Status::Published));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("configure.py")).unwrap(),
            "published\n"
        );
    }

    #[test]
    fn resuming_a_published_run_checks_its_final_certificate_graph() {
        let dir = project();
        let run = RunDir { path: dir.path().join("run") };
        let mut journal = journal(dir.path(), "published\n");
        journal.status = Status::Published;
        let graph = run.path.join("final-certificates.json");
        std::fs::create_dir_all(&run.path).unwrap();
        std::fs::write(&graph, b"first").unwrap();
        journal.final_certificates_sha256 = Some(hash_file_bytes(b"first"));
        write_json(&run.path.join("publication.json"), &journal).unwrap();
        assert_eq!(recover(dir.path(), &run).unwrap(), Some(Status::Published));
        std::fs::write(&graph, b"changed").unwrap();
        assert!(recover(dir.path(), &run).unwrap_err().to_string().contains("certificate graph"));
        journal.final_certificates_sha256 = None;
        write_json(&run.path.join("publication.json"), &journal).unwrap();
        assert!(
            recover(dir.path(), &run).unwrap_err().to_string().contains("no final certificate")
        );
    }

    #[test]
    fn a_run_id_may_not_be_a_path() {
        let dir = project();
        for bad in ["../escape", "a/b", "", ".", ".."] {
            assert!(run_directory(dir.path(), bad).is_err(), "{bad} should be refused");
        }
        assert!(run_directory(dir.path(), "20260916-120000").is_ok());
    }

    #[test]
    fn journal_bytes_round_trip() {
        let bytes = vec![0u8, 1, 127, 128, 255];
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }
}
