//! Backup and undo plumbing for `scan-config --fix`.
//!
//! Each `--fix --yes` run creates a directory under `~/.ramparts/fixes/<run-id>/`
//! containing a `manifest.json` listing every file touched, and one `*.bak`
//! file per touched file holding the pre-fix bytes. `--undo` pops the most
//! recent run-dir, restores each backup, then deletes the run-dir.
//!
//! The manifest stores `sha256_after` so `--undo` can detect that a target file
//! has changed since the fix was applied (e.g., the user edited it manually,
//! or an IDE rewrote it). In that case we skip restoring that entry rather
//! than clobber the user's later edits.

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Per-file record inside a fix run's manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Absolute path to the original IDE config file that was fixed.
    pub target_path: PathBuf,
    /// File name (relative to the run-dir) of the backup copy of the
    /// pre-fix bytes.
    pub backup_filename: String,
    /// SHA-256 of the file contents before the fix was applied.
    pub sha256_before: String,
    /// SHA-256 of the file contents after the fix was applied. `--undo`
    /// uses this to detect drift.
    pub sha256_after: String,
    /// Names of the fix rules that were applied to this file.
    pub applied_rules: Vec<String>,
}

/// One fix run's manifest. Lives at `<run-dir>/manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Run identifier — also the run-dir name. Lex-sortable.
    pub run_id: String,
    /// Ramparts version that produced this manifest.
    pub ramparts_version: String,
    /// ISO-8601 UTC timestamp.
    pub created_at: String,
    /// Per-file entries.
    pub entries: Vec<ManifestEntry>,
}

/// Manages the on-disk backup store at `~/.ramparts/fixes/`.
pub struct BackupStore {
    root: PathBuf,
}

impl BackupStore {
    /// Create a new backup store rooted at `~/.ramparts/fixes/`.
    pub fn new() -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| anyhow!("cannot determine home directory; set $HOME"))?;
        let root = home.join(".ramparts").join("fixes");
        fs::create_dir_all(&root)
            .with_context(|| format!("creating backup store at {}", root.display()))?;
        Ok(Self { root })
    }

    /// Construct a `BackupStore` rooted at an explicit path. Used by tests.
    #[allow(dead_code)] // test-only helper; production uses `new()`
    pub fn with_root(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("creating backup store at {}", root.display()))?;
        Ok(Self { root })
    }

    /// Begin a new fix run. Returns a `RunBuilder` that the caller feeds
    /// `(target_path, original_bytes, fixed_bytes, applied_rules)` tuples
    /// into, then calls `commit()` to write the manifest.
    pub fn begin_run(&self, ramparts_version: &str) -> Result<RunBuilder> {
        let run_id = generate_run_id();
        let run_dir = self.root.join(&run_id);
        fs::create_dir_all(&run_dir)
            .with_context(|| format!("creating run dir {}", run_dir.display()))?;
        Ok(RunBuilder {
            run_dir,
            manifest: Manifest {
                run_id,
                ramparts_version: ramparts_version.to_string(),
                created_at: Utc::now().to_rfc3339(),
                entries: Vec::new(),
            },
        })
    }

    /// Return the most recent (lex-max) run-dir, or `None` if no runs exist.
    pub fn latest_run(&self) -> Result<Option<PathBuf>> {
        if !self.root.exists() {
            return Ok(None);
        }
        let mut runs: Vec<PathBuf> = fs::read_dir(&self.root)
            .with_context(|| format!("reading backup store {}", self.root.display()))?
            .filter_map(|e| e.ok().map(|d| d.path()))
            .filter(|p| p.is_dir() && p.join("manifest.json").exists())
            .collect();
        runs.sort();
        Ok(runs.pop())
    }

    /// Load a manifest from a run-dir.
    pub fn load_manifest(run_dir: &Path) -> Result<Manifest> {
        let path = run_dir.join("manifest.json");
        let bytes =
            fs::read(&path).with_context(|| format!("reading manifest {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing manifest {}", path.display()))
    }

    /// Apply an undo: for each manifest entry, restore the backup if and
    /// only if the current target file's sha256 matches `sha256_after`
    /// (no drift). Skipped entries are returned for caller reporting.
    /// On success the run-dir is deleted.
    pub fn undo(run_dir: &Path) -> Result<UndoReport> {
        let manifest = Self::load_manifest(run_dir)?;
        let mut report = UndoReport::default();
        for entry in &manifest.entries {
            let backup_path = run_dir.join(&entry.backup_filename);
            if !backup_path.exists() {
                report.missing_backup.push(entry.target_path.clone());
                continue;
            }
            // Drift check: refuse to clobber a file the user edited.
            if entry.target_path.exists() {
                let current = fs::read(&entry.target_path).with_context(|| {
                    format!("reading current target {}", entry.target_path.display())
                })?;
                let current_hash = sha256_hex(&current);
                if current_hash != entry.sha256_after {
                    report.skipped_due_to_drift.push(entry.target_path.clone());
                    continue;
                }
            }
            let backup_bytes = fs::read(&backup_path)
                .with_context(|| format!("reading backup {}", backup_path.display()))?;
            // Cheap correctness check on the backup itself.
            if sha256_hex(&backup_bytes) != entry.sha256_before {
                report.corrupt_backup.push(entry.target_path.clone());
                continue;
            }
            atomic_write(&entry.target_path, &backup_bytes)?;
            report.restored.push(entry.target_path.clone());
        }
        // Only clean up the run-dir if nothing went wrong. If anything was
        // skipped or failed, leave the directory so the user can inspect or
        // retry.
        if report.is_clean() {
            fs::remove_dir_all(run_dir)
                .with_context(|| format!("removing run-dir {}", run_dir.display()))?;
        }
        Ok(report)
    }
}

/// A fix run in progress. Accumulates entries, then writes the manifest
/// atomically when `commit()` is called.
pub struct RunBuilder {
    run_dir: PathBuf,
    manifest: Manifest,
}

impl RunBuilder {
    /// Record one file fix. Writes the backup file immediately (so a crash
    /// before `commit()` still leaves recoverable bytes), then writes the
    /// fixed bytes to the target via atomic-rename.
    pub fn record_and_apply(
        &mut self,
        target: &Path,
        original: &[u8],
        fixed: &[u8],
        applied_rules: Vec<String>,
    ) -> Result<()> {
        let sha_before = sha256_hex(original);
        let sha_after = sha256_hex(fixed);
        let backup_filename = format!(
            "{}.bak",
            &sha256_hex(target.to_string_lossy().as_bytes())[..16]
        );
        let backup_path = self.run_dir.join(&backup_filename);
        // Backup BEFORE writing the target — if we crash between these two
        // steps, the original file is on disk untouched and a backup also
        // exists.
        fs::write(&backup_path, original)
            .with_context(|| format!("writing backup {}", backup_path.display()))?;
        atomic_write(target, fixed)?;
        self.manifest.entries.push(ManifestEntry {
            target_path: target.to_path_buf(),
            backup_filename,
            sha256_before: sha_before,
            sha256_after: sha_after,
            applied_rules,
        });
        Ok(())
    }

    /// Finalise the run: write `manifest.json` atomically. If there are zero
    /// entries (all files were no-ops), delete the empty run-dir instead.
    pub fn commit(self) -> Result<Option<PathBuf>> {
        if self.manifest.entries.is_empty() {
            fs::remove_dir_all(&self.run_dir).ok();
            return Ok(None);
        }
        let manifest_path = self.run_dir.join("manifest.json");
        let bytes = serde_json::to_vec_pretty(&self.manifest).context("serializing manifest")?;
        atomic_write(&manifest_path, &bytes)?;
        Ok(Some(self.run_dir))
    }
}

/// Result of an `--undo` operation.
#[derive(Debug, Default)]
pub struct UndoReport {
    pub restored: Vec<PathBuf>,
    pub skipped_due_to_drift: Vec<PathBuf>,
    pub missing_backup: Vec<PathBuf>,
    pub corrupt_backup: Vec<PathBuf>,
}

impl UndoReport {
    pub fn is_clean(&self) -> bool {
        self.skipped_due_to_drift.is_empty()
            && self.missing_backup.is_empty()
            && self.corrupt_backup.is_empty()
    }
}

/// Lex-sortable, collision-resistant run identifier:
/// `YYYYMMDDTHHMMSSZ-<4 hex>`.
fn generate_run_id() -> String {
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ");
    let suffix: u16 = rand::rng().random();
    format!("{ts}-{suffix:04x}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        write!(&mut out, "{b:02x}").unwrap();
    }
    out
}

/// Atomic-on-Unix, replace-existing-on-Windows write via tempfile + persist.
/// Caveat (documented in `docs/cli.md`): we call `fsync(2)` on Unix, which
/// on macOS does NOT guarantee platter durability — `F_FULLFSYNC` would.
/// We accept this tradeoff for v1; backups make a crash recoverable.
fn atomic_write(target: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = target
        .parent()
        .ok_or_else(|| anyhow!("target has no parent: {}", target.display()))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating tempfile in {}", parent.display()))?;
    tmp.write_all(bytes)
        .with_context(|| format!("writing tempfile for {}", target.display()))?;
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("fsync tempfile for {}", target.display()))?;
    tmp.persist(target)
        .map_err(|e| anyhow!("persist tempfile to {}: {}", target.display(), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn manifest_round_trip() {
        let m = Manifest {
            run_id: "20260101T000000Z-abcd".into(),
            ramparts_version: "0.7.0".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            entries: vec![ManifestEntry {
                target_path: PathBuf::from("/tmp/x.json"),
                backup_filename: "deadbeef.bak".into(),
                sha256_before: "a".repeat(64),
                sha256_after: "b".repeat(64),
                applied_rules: vec!["http-to-https".into()],
            }],
        };
        let bytes = serde_json::to_vec(&m).unwrap();
        let parsed: Manifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.run_id, m.run_id);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].applied_rules[0], "http-to-https");
    }

    #[test]
    fn run_id_is_unique_and_sortable() {
        let mut ids: Vec<String> = (0..50).map(|_| generate_run_id()).collect();
        let len_before = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "run-ids should be unique");
    }

    #[test]
    fn record_apply_and_undo_round_trip() {
        let store_dir = TempDir::new().unwrap();
        let work = TempDir::new().unwrap();
        let target = work.path().join("config.json");
        let original = b"{\"mcpServers\":{\"x\":{\"url\":\"http://example.com\"}}}";
        let fixed = b"{\"mcpServers\":{\"x\":{\"url\":\"https://example.com\"}}}";
        fs::write(&target, original).unwrap();

        let store = BackupStore::with_root(store_dir.path().to_path_buf()).unwrap();
        let mut run = store.begin_run("test").unwrap();
        run.record_and_apply(&target, original, fixed, vec!["http-to-https".into()])
            .unwrap();
        let run_dir = run.commit().unwrap().expect("manifest written");

        // Target should now hold the fixed bytes.
        assert_eq!(fs::read(&target).unwrap(), fixed);

        // Undo: byte-identical restore.
        let report = BackupStore::undo(&run_dir).unwrap();
        assert_eq!(report.restored.len(), 1);
        assert!(report.is_clean());
        assert_eq!(fs::read(&target).unwrap(), original);
        // Run-dir cleaned up on clean undo.
        assert!(!run_dir.exists());
    }

    #[test]
    fn undo_skips_files_modified_since_fix() {
        let store_dir = TempDir::new().unwrap();
        let work = TempDir::new().unwrap();
        let target = work.path().join("config.json");
        let original = b"original";
        let fixed = b"fixed";
        fs::write(&target, original).unwrap();

        let store = BackupStore::with_root(store_dir.path().to_path_buf()).unwrap();
        let mut run = store.begin_run("test").unwrap();
        run.record_and_apply(&target, original, fixed, vec!["test".into()])
            .unwrap();
        let run_dir = run.commit().unwrap().unwrap();

        // User edits the file after the fix.
        fs::write(&target, b"user-edited-since-fix").unwrap();

        let report = BackupStore::undo(&run_dir).unwrap();
        assert_eq!(report.restored.len(), 0);
        assert_eq!(report.skipped_due_to_drift.len(), 1);
        // User's edit preserved.
        assert_eq!(fs::read(&target).unwrap(), b"user-edited-since-fix");
        // Run-dir kept (not clean) so the user can inspect.
        assert!(run_dir.exists());
    }

    #[test]
    fn latest_run_returns_lex_max() {
        let store_dir = TempDir::new().unwrap();
        let store = BackupStore::with_root(store_dir.path().to_path_buf()).unwrap();
        // No runs.
        assert!(store.latest_run().unwrap().is_none());

        // Manually create three run-dirs in non-sorted order.
        for id in [
            "20260101T000000Z-0001",
            "20260301T000000Z-0001",
            "20260201T000000Z-0001",
        ] {
            let d = store_dir.path().join(id);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("manifest.json"), "{}").unwrap();
        }
        let latest = store.latest_run().unwrap().unwrap();
        assert!(latest.to_string_lossy().ends_with("20260301T000000Z-0001"));
    }

    #[test]
    fn empty_run_does_not_persist_dir() {
        let store_dir = TempDir::new().unwrap();
        let store = BackupStore::with_root(store_dir.path().to_path_buf()).unwrap();
        let run = store.begin_run("test").unwrap();
        let result = run.commit().unwrap();
        assert!(result.is_none());
        // No leftover run-dirs.
        let entries: Vec<_> = fs::read_dir(store_dir.path()).unwrap().collect();
        assert!(entries.is_empty());
    }
}
