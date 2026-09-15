//! Writing proposed split boundaries in `splits.txt` syntax.

use std::{collections::BTreeMap, io::Write};

use anyhow::Result;
use decomp_toolkit::util::file::buf_writer;
use tracing::info;
use typed_path::Utf8NativePath;

use crate::analysis::{
    matching::MatchTarget,
    unit_matching::{UnitProposal, UnitTier},
};

/// Writes proposed split boundaries in splits.txt syntax, grouped by unit.
/// Confident entries are real lines; candidates are commented out with the
/// reason they weren't confident, so the file is ready to paste from once
/// reviewed.
pub fn write_unit_proposals(
    path: &Utf8NativePath,
    target: &MatchTarget,
    proposals: &[UnitProposal],
) -> Result<()> {
    let mut file = buf_writer(path)?;
    writeln!(file, "# Proposed split boundaries, derived from function matches.")?;
    writeln!(file, "#")?;
    writeln!(file, "# Confident entries are ready to paste into a splits.txt. Candidates are")?;
    writeln!(file, "# commented out, with the reason they weren't confident; review before")?;
    writeln!(file, "# uncommenting.")?;
    writeln!(file)?;

    let mut by_unit: BTreeMap<&str, Vec<&UnitProposal>> = BTreeMap::new();
    for p in proposals {
        by_unit.entry(p.unit.as_str()).or_default().push(p);
    }

    let (mut confident, mut candidates) = (0, 0);
    for (unit, entries) in by_unit {
        writeln!(file, "{unit}:")?;
        for p in entries {
            let section_name =
                target.obj.sections.get(p.section).map(|s| s.name.as_str()).unwrap_or("?");
            let line =
                format!("\t{:<11} start:{:#010X} end:{:#010X}", section_name, p.start, p.end);
            match p.tier {
                UnitTier::Confident => {
                    writeln!(file, "{line}")?;
                    confident += 1;
                }
                UnitTier::Candidate => {
                    writeln!(file, "#{line}  # candidate: {}", p.reasons.join("; "))?;
                    candidates += 1;
                }
            }
        }
        writeln!(file)?;
    }
    file.flush()?;
    info!(
        "Wrote {} confident and {} candidate split boundaries to {}",
        confident, candidates, path
    );
    Ok(())
}
