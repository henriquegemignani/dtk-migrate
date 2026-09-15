//! Owning a project file for the duration of a trial, and giving it back.
//!
//! A stage rewrites `splits.txt`, `symbols.txt` or `configure.py`, builds, and
//! then either keeps the change or undoes it. Two things make that harder than
//! it sounds. The workspace may be the user's own checkout in a serial run, so
//! an edit made while we are building is theirs and must not be clobbered. And
//! a crash mid-trial must not leave a half-written file that looks like a
//! deliberate change.
//!
//! So every write states what it believes the file currently contains, refuses
//! if that is wrong, and lands atomically. Dropping without committing restores
//! the original — unless someone else has edited it since, in which case their
//! version stands and the error says so.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The file changed outside the transaction that owns it.
#[derive(Debug)]
pub struct ConfigChangedError(pub String);

impl std::fmt::Display for ConfigChangedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

impl std::error::Error for ConfigChangedError {}

/// A project file this transaction is allowed to rewrite.
pub struct Owned {
    path: PathBuf,
    original: Vec<u8>,
    current: Vec<u8>,
    committed: bool,
}

impl Owned {
    pub fn take(path: &Path) -> Result<Self> {
        let original =
            std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
        Ok(Self { path: path.to_path_buf(), current: original.clone(), original, committed: false })
    }

    pub fn path(&self) -> &Path { &self.path }

    pub fn original(&self) -> &[u8] { &self.original }

    /// What this transaction last wrote, which is what a caller must hand back
    /// to undo one step without undoing the others.
    pub fn current(&self) -> &[u8] { &self.current }

    /// Confirms the file still holds what this transaction last wrote.
    pub fn check(&self) -> Result<()> {
        match std::fs::read(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                bail!(ConfigChangedError(format!(
                    "{} disappeared during a trial",
                    self.path.display()
                )))
            }
            Err(e) => Err(e).with_context(|| format!("Failed to read {}", self.path.display())),
            Ok(current) if current != self.current => bail!(ConfigChangedError(format!(
                "{} changed during a trial; preserving those edits",
                self.path.display()
            ))),
            Ok(_) => Ok(()),
        }
    }

    /// Atomically replaces the file, after confirming we still own it.
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.check()?;
        if self.current == bytes {
            return Ok(());
        }
        let directory = self.path.parent().unwrap_or(Path::new("."));
        let mut temporary = tempfile::Builder::new()
            .prefix(&format!(".{}.", file_name(&self.path)))
            .suffix(".tmp")
            .tempfile_in(directory)?;
        use std::io::Write;
        temporary.write_all(bytes)?;
        temporary.as_file().sync_all()?;
        // Re-check as late as possible: the window between deciding to write and
        // writing is where a concurrent edit would be lost.
        self.check()?;
        temporary.persist(&self.path).map_err(|e| e.error)?;
        self.current = bytes.to_vec();
        Ok(())
    }

    /// Puts the original contents back.
    pub fn restore(&mut self) -> Result<()> {
        let original = self.original.clone();
        self.write(&original)
    }

    /// Keeps whatever is currently written when this goes out of scope.
    pub fn commit(mut self) { self.committed = true; }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if self.committed || self.current == self.original {
            return;
        }
        // Never overwrite an intervening edit, and never mask the error that
        // brought us here.
        let _ = self.restore();
    }
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("configure.py");
        std::fs::write(&path, contents).unwrap();
        (dir, path)
    }

    #[test]
    fn an_uncommitted_change_is_undone_when_the_transaction_ends() {
        let (_dir, path) = file("before");
        {
            let mut owned = Owned::take(&path).unwrap();
            owned.write(b"after").unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "after");
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "before");
    }

    #[test]
    fn a_committed_change_stays() {
        let (_dir, path) = file("before");
        {
            let mut owned = Owned::take(&path).unwrap();
            owned.write(b"after").unwrap();
            owned.commit();
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after");
    }

    #[test]
    fn writing_over_someone_elses_edit_is_refused() {
        let (_dir, path) = file("before");
        let mut owned = Owned::take(&path).unwrap();
        std::fs::write(&path, "theirs").unwrap();
        let error = owned.write(b"ours").unwrap_err();
        assert!(error.downcast_ref::<ConfigChangedError>().is_some(), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "theirs");
    }

    #[test]
    fn an_intervening_edit_survives_the_rollback() {
        let (_dir, path) = file("before");
        {
            let mut owned = Owned::take(&path).unwrap();
            owned.write(b"ours").unwrap();
            std::fs::write(&path, "theirs").unwrap();
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "theirs");
    }

    #[test]
    fn a_deleted_file_is_reported_rather_than_recreated() {
        let (_dir, path) = file("before");
        let owned = Owned::take(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(owned.check().unwrap_err().to_string().contains("disappeared"));
    }

    #[test]
    fn writing_the_same_bytes_is_a_no_op() {
        let (_dir, path) = file("same");
        let mut owned = Owned::take(&path).unwrap();
        owned.write(b"same").unwrap();
        assert!(owned.check().is_ok());
    }

    #[test]
    fn no_temporary_files_are_left_behind() {
        let (dir, path) = file("before");
        {
            let mut owned = Owned::take(&path).unwrap();
            owned.write(b"after").unwrap();
            owned.commit();
        }
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name != "configure.py")
            .collect();
        assert!(left.is_empty(), "{left:?}");
    }
}
