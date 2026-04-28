use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use veil_domain::{
    ArtifactId, ArtifactState, InputCorpusId, PolicyId, QuarantineReasonCode, RunId,
    SourceLocatorHash,
};

use crate::schema::LedgerSchemaVersion;

/// Wire-format ledger schema version emitted by the current writer.
///
/// Re-exported from [`crate::LedgerSchemaVersion::CURRENT`] so existing
/// `veil_evidence::LEDGER_SCHEMA_VERSION` callers stay source-compatible
/// during the schema-enum migration.
pub const LEDGER_SCHEMA_VERSION: &str = LedgerSchemaVersion::CURRENT.as_str();

/// Default busy-timeout for SQLite operations. WAL mode tolerates a single
/// writer + many readers but may briefly block if a checkpoint is in flight;
/// the busy-timeout makes that retry transparently.
const LEDGER_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("ledger io error")]
    Io,
    #[error("ledger sql error")]
    Sql,
    #[error("ledger schema unsupported")]
    UnsupportedSchema,
    #[error("ledger missing required meta key")]
    MissingMeta,
}

#[derive(Debug, Clone)]
pub struct ArtifactSummary {
    pub state: ArtifactState,
    pub quarantine_reason_code: Option<String>,
    pub output_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArtifactRecord {
    pub artifact_id: ArtifactId,
    pub source_locator_hash: SourceLocatorHash,
    pub size_bytes: u64,
    pub artifact_type: String,
    pub state: ArtifactState,
    pub quarantine_reason_code: Option<String>,
    pub output_id: Option<String>,
}

pub struct Ledger {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct FindingsSummaryRow<'a> {
    pub class_id: &'a str,
    pub severity: &'a str,
    pub action: &'a str,
    pub count: u64,
}

/// Configure WAL + busy-timeout pragmas on a freshly opened connection.
///
/// Phase 4 of the cleanup plan introduces `--max-workers` parallelism; under
/// parallel pipelines we still funnel ledger writes through a single committer
/// thread, but the readers (residual verification, metadata queries) now run
/// concurrently. WAL mode is the prerequisite for that read/write concurrency.
fn apply_runtime_pragmas(conn: &Connection) -> Result<(), LedgerError> {
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| LedgerError::Sql)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|_| LedgerError::Sql)?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|_| LedgerError::Sql)?;
    conn.busy_timeout(LEDGER_BUSY_TIMEOUT)
        .map_err(|_| LedgerError::Sql)?;
    Ok(())
}

impl Ledger {
    pub fn create_new(
        path: &Path,
        tool_version: &str,
        policy_id: &PolicyId,
        run_id: &RunId,
        input_corpus_id: &InputCorpusId,
    ) -> Result<Self, LedgerError> {
        if path.exists() {
            return Err(LedgerError::Io);
        }
        let conn = Connection::open(path).map_err(|_| LedgerError::Io)?;
        apply_runtime_pragmas(&conn)?;

        // Fresh DBs gain a composite PRIMARY KEY on findings_summary so
        // duplicate (artifact_id, class_id, severity, action) rows can never
        // accumulate even if a future writer skips the explicit DELETE
        // before re-INSERT. Existing callers (`replace_findings_summary`)
        // continue to DELETE-then-INSERT, which the PK accepts. Old packs
        // opened via `open_existing` lack the PK; that's fine because the
        // schema-version negotiation rejects schema drift.
        //
        // V2 adds the `proof_tokens` table so resume no longer parses
        // `evidence/artifacts.ndjson` to recover proof tokens. The table
        // is keyed (artifact_id, token_index) so tokens stay
        // insertion-ordered per artifact and duplicates are impossible.
        conn.execute_batch(create_v2_schema_sql())
            .map_err(|_| LedgerError::Sql)?;

        let ledger = Self { conn };
        ledger.set_meta("schema_version", LedgerSchemaVersion::CURRENT.as_str())?;
        ledger.set_meta("tool_version", tool_version)?;
        ledger.set_meta("policy_id", &policy_id.to_string())?;
        ledger.set_meta("run_id", &run_id.to_string())?;
        ledger.set_meta("input_corpus_id", &input_corpus_id.to_string())?;

        Ok(ledger)
    }

    pub fn open_existing(path: &Path) -> Result<Self, LedgerError> {
        if !path.exists() {
            return Err(LedgerError::Io);
        }
        let conn = Connection::open(path).map_err(|_| LedgerError::Io)?;
        apply_runtime_pragmas(&conn)?;
        let mut ledger = Self { conn };
        let schema_version = ledger
            .get_meta("schema_version")?
            .ok_or(LedgerError::MissingMeta)?;
        let parsed = LedgerSchemaVersion::parse(&schema_version)
            .map_err(|_| LedgerError::UnsupportedSchema)?;
        if parsed != LedgerSchemaVersion::CURRENT {
            // The migrator is the read path's escape hatch: V1 packs are
            // legitimate inputs (they predate the proof-tokens table) so
            // we upgrade them in place to V2 before any caller can see them.
            ledger.migrate_to_current(parsed)?;
        }
        Ok(ledger)
    }

    /// Bring an opened ledger up to `LedgerSchemaVersion::CURRENT`.
    ///
    /// Currently the only supported migration is V1 -> V2, which adds the
    /// `proof_tokens` table and bumps the meta `schema_version` row.
    /// `CREATE TABLE IF NOT EXISTS` keeps the migration idempotent.
    pub fn migrate_to_current(&mut self, from: LedgerSchemaVersion) -> Result<(), LedgerError> {
        match from {
            LedgerSchemaVersion::V2 => Ok(()),
            LedgerSchemaVersion::V1 => {
                // The proof_tokens table must exist before any caller queries
                // it. Wrap in a transaction so the schema bump is atomic with
                // the meta update.
                let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
                tx.execute_batch(proof_tokens_table_sql())
                    .map_err(|_| LedgerError::Sql)?;
                tx.execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2) \
                     ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    params!["schema_version", LedgerSchemaVersion::V2.as_str()],
                )
                .map_err(|_| LedgerError::Sql)?;
                tx.commit().map_err(|_| LedgerError::Sql)?;
                Ok(())
            }
        }
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>, LedgerError> {
        self.conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| LedgerError::Sql)
    }

    pub fn upsert_meta(&self, key: &str, value: &str) -> Result<(), LedgerError> {
        self.set_meta(key, value)
    }

    pub fn artifact_summary(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<Option<ArtifactSummary>, LedgerError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT state, quarantine_reason_code, output_id FROM artifacts WHERE artifact_id = ?1",
            )
            .map_err(|_| LedgerError::Sql)?;

        let mut rows = stmt
            .query(params![artifact_id.to_string()])
            .map_err(|_| LedgerError::Sql)?;
        let Some(row) = rows.next().map_err(|_| LedgerError::Sql)? else {
            return Ok(None);
        };

        let raw_state = row.get::<_, String>(0).map_err(|_| LedgerError::Sql)?;
        let state = parse_artifact_state(&raw_state).ok_or(LedgerError::Sql)?;
        let quarantine_reason_code = row
            .get::<_, Option<String>>(1)
            .map_err(|_| LedgerError::Sql)?;
        let output_id = row
            .get::<_, Option<String>>(2)
            .map_err(|_| LedgerError::Sql)?;
        Ok(Some(ArtifactSummary {
            state,
            quarantine_reason_code,
            output_id,
        }))
    }

    pub fn artifact_records(&self) -> Result<Vec<ArtifactRecord>, LedgerError> {
        let mut stmt = self
            .conn
            .prepare(
                r#"
SELECT artifact_id, source_locator_hash, size_bytes, artifact_type, state, quarantine_reason_code, output_id
FROM artifacts
ORDER BY artifact_id
"#,
            )
            .map_err(|_| LedgerError::Sql)?;

        let rows = stmt
            .query_map([], |row| {
                let artifact_id = row.get::<_, String>(0)?;
                let source_locator_hash = row.get::<_, String>(1)?;
                let size_bytes = row.get::<_, i64>(2)?;
                let artifact_type = row.get::<_, String>(3)?;
                let raw_state = row.get::<_, String>(4)?;
                let quarantine_reason_code = row.get::<_, Option<String>>(5)?;
                let output_id = row.get::<_, Option<String>>(6)?;
                Ok((
                    artifact_id,
                    source_locator_hash,
                    size_bytes,
                    artifact_type,
                    raw_state,
                    quarantine_reason_code,
                    output_id,
                ))
            })
            .map_err(|_| LedgerError::Sql)?;

        let mut out = Vec::new();
        for row in rows {
            let (
                artifact_id,
                source_locator_hash,
                size_bytes,
                artifact_type,
                raw_state,
                quarantine_reason_code,
                output_id,
            ) = row.map_err(|_| LedgerError::Sql)?;
            let artifact_id = ArtifactId::from_hex(&artifact_id).map_err(|_| LedgerError::Sql)?;
            let source_locator_hash =
                SourceLocatorHash::from_hex(&source_locator_hash).map_err(|_| LedgerError::Sql)?;
            let state = parse_artifact_state(&raw_state).ok_or(LedgerError::Sql)?;
            let size_bytes = u64::try_from(size_bytes).map_err(|_| LedgerError::Sql)?;
            out.push(ArtifactRecord {
                artifact_id,
                source_locator_hash,
                size_bytes,
                artifact_type,
                state,
                quarantine_reason_code,
                output_id,
            });
        }
        Ok(out)
    }

    pub fn quarantine_artifact(
        &mut self,
        artifact_id: &ArtifactId,
        source_locator_hash: &SourceLocatorHash,
        size_bytes: u64,
        artifact_type: &str,
        reason: QuarantineReasonCode,
    ) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
        quarantine_artifact_in_tx(
            &tx,
            artifact_id,
            source_locator_hash,
            size_bytes,
            artifact_type,
            reason,
        )?;
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    pub fn upsert_discovered(
        &mut self,
        artifact_id: &ArtifactId,
        source_locator_hash: &SourceLocatorHash,
        size_bytes: u64,
        artifact_type: &str,
    ) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
        upsert_discovered_in_tx(
            &tx,
            artifact_id,
            source_locator_hash,
            size_bytes,
            artifact_type,
        )?;
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    pub fn mark_extracted(
        &mut self,
        artifact_id: &ArtifactId,
        extractor_id: &str,
        coverage_hash: &str,
    ) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
        mark_extracted_in_tx(&tx, artifact_id, extractor_id, coverage_hash)?;
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    pub fn mark_transformed(&mut self, artifact_id: &ArtifactId) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
        mark_transformed_in_tx(&tx, artifact_id)?;
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    pub fn mark_verified(
        &mut self,
        artifact_id: &ArtifactId,
        output_id: &str,
    ) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
        mark_verified_in_tx(&tx, artifact_id, output_id)?;
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    pub fn quarantine(
        &mut self,
        artifact_id: &ArtifactId,
        reason: QuarantineReasonCode,
    ) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
        quarantine_in_tx(&tx, artifact_id, reason)?;
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    pub fn replace_findings_summary(
        &mut self,
        artifact_id: &ArtifactId,
        rows: &[FindingsSummaryRow<'_>],
    ) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
        replace_findings_summary_in_tx(&tx, artifact_id, rows)?;
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    /// Replace the proof-token list for one artifact atomically. DELETE
    /// then INSERT — same pattern as `replace_findings_summary`. Tokens
    /// are stored with their position so reads return them in the same
    /// order they were emitted by the detector.
    pub fn replace_proof_tokens(
        &mut self,
        artifact_id: &ArtifactId,
        tokens: &[String],
    ) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
        replace_proof_tokens_in_tx(&tx, artifact_id, tokens)?;
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    /// Read the proof-token list for one artifact, ordered by insertion
    /// index. An empty result is returned for unknown artifacts (matches
    /// the legacy `load_existing_proof_tokens` "no-token" semantics).
    pub fn proof_tokens_for(&self, artifact_id: &ArtifactId) -> Result<Vec<String>, LedgerError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT token FROM proof_tokens WHERE artifact_id = ?1 ORDER BY token_index ASC",
            )
            .map_err(|_| LedgerError::Sql)?;

        let rows = stmt
            .query_map(params![artifact_id.to_string()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|_| LedgerError::Sql)?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|_| LedgerError::Sql)?);
        }
        Ok(out)
    }

    /// Open a [`LedgerTransaction`] that batches multiple writes into a single
    /// atomic commit. Drop without `commit()` rolls back. Used by the
    /// per-artifact pipeline so the four state transitions (extract,
    /// transform, verify, findings_summary) collapse to one fsync rather
    /// than four. This is also the parallelism-friendly seam: under the
    /// Phase 4 worker pool, one committer thread receives per-artifact
    /// outcomes and applies each as a single batched transaction.
    pub fn transaction(&mut self) -> Result<LedgerTransaction<'_>, LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
        Ok(LedgerTransaction { tx })
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<(), LedgerError> {
        self.conn
            .execute(
                r#"
INSERT INTO meta (key, value) VALUES (?1, ?2)
ON CONFLICT(key) DO UPDATE SET value=excluded.value
"#,
                params![key, value],
            )
            .map_err(|_| LedgerError::Sql)?;
        Ok(())
    }
}

/// Held transaction guard. Mirrors `mark_*` / `quarantine_*` /
/// `replace_findings_summary` but defers commit until the caller invokes
/// `commit()` explicitly. Drop without `commit()` rolls back the held
/// transaction (`rusqlite::Transaction::Drop` rolls back by default).
pub struct LedgerTransaction<'a> {
    tx: Transaction<'a>,
}

impl<'a> LedgerTransaction<'a> {
    pub fn upsert_discovered(
        &self,
        artifact_id: &ArtifactId,
        source_locator_hash: &SourceLocatorHash,
        size_bytes: u64,
        artifact_type: &str,
    ) -> Result<(), LedgerError> {
        upsert_discovered_in_tx(
            &self.tx,
            artifact_id,
            source_locator_hash,
            size_bytes,
            artifact_type,
        )
    }

    pub fn mark_extracted(
        &self,
        artifact_id: &ArtifactId,
        extractor_id: &str,
        coverage_hash: &str,
    ) -> Result<(), LedgerError> {
        mark_extracted_in_tx(&self.tx, artifact_id, extractor_id, coverage_hash)
    }

    pub fn mark_transformed(&self, artifact_id: &ArtifactId) -> Result<(), LedgerError> {
        mark_transformed_in_tx(&self.tx, artifact_id)
    }

    pub fn mark_verified(
        &self,
        artifact_id: &ArtifactId,
        output_id: &str,
    ) -> Result<(), LedgerError> {
        mark_verified_in_tx(&self.tx, artifact_id, output_id)
    }

    pub fn quarantine(
        &self,
        artifact_id: &ArtifactId,
        reason: QuarantineReasonCode,
    ) -> Result<(), LedgerError> {
        quarantine_in_tx(&self.tx, artifact_id, reason)
    }

    pub fn quarantine_artifact(
        &self,
        artifact_id: &ArtifactId,
        source_locator_hash: &SourceLocatorHash,
        size_bytes: u64,
        artifact_type: &str,
        reason: QuarantineReasonCode,
    ) -> Result<(), LedgerError> {
        quarantine_artifact_in_tx(
            &self.tx,
            artifact_id,
            source_locator_hash,
            size_bytes,
            artifact_type,
            reason,
        )
    }

    pub fn replace_findings_summary(
        &self,
        artifact_id: &ArtifactId,
        rows: &[FindingsSummaryRow<'_>],
    ) -> Result<(), LedgerError> {
        replace_findings_summary_in_tx(&self.tx, artifact_id, rows)
    }

    /// Same semantics as [`Ledger::replace_proof_tokens`] but executed
    /// inside the held transaction so it commits atomically with the
    /// surrounding state transitions.
    pub fn replace_proof_tokens(
        &self,
        artifact_id: &ArtifactId,
        tokens: &[String],
    ) -> Result<(), LedgerError> {
        replace_proof_tokens_in_tx(&self.tx, artifact_id, tokens)
    }

    pub fn commit(self) -> Result<(), LedgerError> {
        self.tx.commit().map_err(|_| LedgerError::Sql)
    }
}

fn upsert_discovered_in_tx(
    tx: &Transaction<'_>,
    artifact_id: &ArtifactId,
    source_locator_hash: &SourceLocatorHash,
    size_bytes: u64,
    artifact_type: &str,
) -> Result<(), LedgerError> {
    tx.execute(
        r#"
INSERT INTO artifacts (
  artifact_id,
  source_locator_hash,
  size_bytes,
  artifact_type,
  state,
  quarantine_reason_code,
  extractor_id,
  coverage_hash,
  output_id
) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL, NULL)
ON CONFLICT(artifact_id) DO UPDATE SET
  source_locator_hash=excluded.source_locator_hash,
  size_bytes=excluded.size_bytes,
  artifact_type=excluded.artifact_type
WHERE artifacts.state NOT IN ('VERIFIED', 'QUARANTINED')
"#,
        params![
            artifact_id.to_string(),
            source_locator_hash.to_string(),
            i64::try_from(size_bytes).unwrap_or(i64::MAX),
            artifact_type,
            ArtifactState::Discovered.as_str(),
        ],
    )
    .map_err(|_| LedgerError::Sql)?;
    Ok(())
}

fn quarantine_artifact_in_tx(
    tx: &Transaction<'_>,
    artifact_id: &ArtifactId,
    source_locator_hash: &SourceLocatorHash,
    size_bytes: u64,
    artifact_type: &str,
    reason: QuarantineReasonCode,
) -> Result<(), LedgerError> {
    tx.execute(
        r#"
INSERT INTO artifacts (
  artifact_id,
  source_locator_hash,
  size_bytes,
  artifact_type,
  state,
  quarantine_reason_code,
  extractor_id,
  coverage_hash,
  output_id
) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL, NULL)
ON CONFLICT(artifact_id) DO UPDATE SET
  source_locator_hash=excluded.source_locator_hash,
  size_bytes=excluded.size_bytes,
  artifact_type=excluded.artifact_type
WHERE artifacts.state NOT IN ('VERIFIED', 'QUARANTINED')
"#,
        params![
            artifact_id.to_string(),
            source_locator_hash.to_string(),
            i64::try_from(size_bytes).unwrap_or(i64::MAX),
            artifact_type,
            ArtifactState::Discovered.as_str(),
        ],
    )
    .map_err(|_| LedgerError::Sql)?;

    tx.execute(
        r#"
UPDATE artifacts
SET state=?2, quarantine_reason_code=?3,
    extractor_id=NULL, coverage_hash=NULL, output_id=NULL
WHERE artifact_id=?1 AND state NOT IN ('VERIFIED', 'QUARANTINED')
"#,
        params![
            artifact_id.to_string(),
            ArtifactState::Quarantined.as_str(),
            reason.as_str()
        ],
    )
    .map_err(|_| LedgerError::Sql)?;
    Ok(())
}

fn mark_extracted_in_tx(
    tx: &Transaction<'_>,
    artifact_id: &ArtifactId,
    extractor_id: &str,
    coverage_hash: &str,
) -> Result<(), LedgerError> {
    tx.execute(
        r#"
UPDATE artifacts
SET state=?2,
    extractor_id=?3,
    coverage_hash=?4,
    quarantine_reason_code=NULL,
    output_id=NULL
WHERE artifact_id=?1 AND state NOT IN ('VERIFIED', 'QUARANTINED')
"#,
        params![
            artifact_id.to_string(),
            ArtifactState::Extracted.as_str(),
            extractor_id,
            coverage_hash
        ],
    )
    .map_err(|_| LedgerError::Sql)?;
    Ok(())
}

fn mark_transformed_in_tx(
    tx: &Transaction<'_>,
    artifact_id: &ArtifactId,
) -> Result<(), LedgerError> {
    tx.execute(
        r#"
UPDATE artifacts
SET state=?2
WHERE artifact_id=?1 AND state NOT IN ('VERIFIED', 'QUARANTINED')
"#,
        params![artifact_id.to_string(), ArtifactState::Transformed.as_str()],
    )
    .map_err(|_| LedgerError::Sql)?;
    Ok(())
}

fn mark_verified_in_tx(
    tx: &Transaction<'_>,
    artifact_id: &ArtifactId,
    output_id: &str,
) -> Result<(), LedgerError> {
    tx.execute(
        r#"
UPDATE artifacts
SET state=?2,
    quarantine_reason_code=NULL,
    output_id=?3
WHERE artifact_id=?1 AND state NOT IN ('VERIFIED', 'QUARANTINED')
"#,
        params![
            artifact_id.to_string(),
            ArtifactState::Verified.as_str(),
            output_id
        ],
    )
    .map_err(|_| LedgerError::Sql)?;
    Ok(())
}

fn quarantine_in_tx(
    tx: &Transaction<'_>,
    artifact_id: &ArtifactId,
    reason: QuarantineReasonCode,
) -> Result<(), LedgerError> {
    tx.execute(
        r#"
UPDATE artifacts
SET state=?2,
    quarantine_reason_code=?3,
    output_id=NULL
WHERE artifact_id=?1 AND state NOT IN ('VERIFIED', 'QUARANTINED')
"#,
        params![
            artifact_id.to_string(),
            ArtifactState::Quarantined.as_str(),
            reason.as_str()
        ],
    )
    .map_err(|_| LedgerError::Sql)?;
    Ok(())
}

fn replace_findings_summary_in_tx(
    tx: &Transaction<'_>,
    artifact_id: &ArtifactId,
    rows: &[FindingsSummaryRow<'_>],
) -> Result<(), LedgerError> {
    tx.execute(
        "DELETE FROM findings_summary WHERE artifact_id=?1",
        params![artifact_id.to_string()],
    )
    .map_err(|_| LedgerError::Sql)?;

    for r in rows {
        tx.execute(
            r#"
INSERT INTO findings_summary (artifact_id, class_id, severity, action, count)
VALUES (?1, ?2, ?3, ?4, ?5)
"#,
            params![
                artifact_id.to_string(),
                r.class_id,
                r.severity,
                r.action,
                i64::try_from(r.count).unwrap_or(i64::MAX)
            ],
        )
        .map_err(|_| LedgerError::Sql)?;
    }
    Ok(())
}

fn replace_proof_tokens_in_tx(
    tx: &Transaction<'_>,
    artifact_id: &ArtifactId,
    tokens: &[String],
) -> Result<(), LedgerError> {
    tx.execute(
        "DELETE FROM proof_tokens WHERE artifact_id=?1",
        params![artifact_id.to_string()],
    )
    .map_err(|_| LedgerError::Sql)?;

    for (idx, token) in tokens.iter().enumerate() {
        let token_index = i64::try_from(idx).map_err(|_| LedgerError::Sql)?;
        tx.execute(
            "INSERT INTO proof_tokens (artifact_id, token_index, token) VALUES (?1, ?2, ?3)",
            params![artifact_id.to_string(), token_index, token],
        )
        .map_err(|_| LedgerError::Sql)?;
    }
    Ok(())
}

/// SQL emitted into a fresh DB by [`Ledger::create_new`].
///
/// Returned as a single batch so all tables and indexes are created inside
/// one transaction. The helper is also used by the ledger v1->v2 migrator
/// so the proof_tokens table layout has exactly one source of truth.
const fn create_v2_schema_sql() -> &'static str {
    r#"
BEGIN;
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY,
  source_locator_hash TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  artifact_type TEXT NOT NULL,
  state TEXT NOT NULL,
  quarantine_reason_code TEXT NULL,
  extractor_id TEXT NULL,
  coverage_hash TEXT NULL,
  output_id TEXT NULL
);

CREATE TABLE IF NOT EXISTS findings_summary (
  artifact_id TEXT NOT NULL,
  class_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  action TEXT NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (artifact_id, class_id, severity, action),
  FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
);

CREATE TABLE IF NOT EXISTS proof_tokens (
  artifact_id TEXT NOT NULL,
  token_index INTEGER NOT NULL,
  token TEXT NOT NULL,
  PRIMARY KEY (artifact_id, token_index),
  FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
);

CREATE INDEX IF NOT EXISTS artifacts_state_idx ON artifacts(state);
CREATE INDEX IF NOT EXISTS findings_class_id_idx ON findings_summary(class_id);
CREATE INDEX IF NOT EXISTS proof_tokens_artifact_idx ON proof_tokens(artifact_id);
COMMIT;
"#
}

/// SQL run by the v1->v2 migrator to add only the proof_tokens table and
/// its index. CREATE TABLE / INDEX IF NOT EXISTS makes the migration safe
/// to run repeatedly even if a partial migration left the table behind.
const fn proof_tokens_table_sql() -> &'static str {
    r#"
CREATE TABLE IF NOT EXISTS proof_tokens (
  artifact_id TEXT NOT NULL,
  token_index INTEGER NOT NULL,
  token TEXT NOT NULL,
  PRIMARY KEY (artifact_id, token_index),
  FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
);
CREATE INDEX IF NOT EXISTS proof_tokens_artifact_idx ON proof_tokens(artifact_id);
"#
}

fn parse_artifact_state(s: &str) -> Option<ArtifactState> {
    match s {
        "DISCOVERED" => Some(ArtifactState::Discovered),
        "EXTRACTED" => Some(ArtifactState::Extracted),
        "TRANSFORMED" => Some(ArtifactState::Transformed),
        "VERIFIED" => Some(ArtifactState::Verified),
        "QUARANTINED" => Some(ArtifactState::Quarantined),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use veil_domain::{Digest32, InputCorpusId, PolicyId, RunId};

    fn dummy_ids() -> (PolicyId, RunId, InputCorpusId) {
        (
            PolicyId::from_digest(Digest32::from_bytes([1_u8; 32])),
            RunId::from_digest(Digest32::from_bytes([2_u8; 32])),
            InputCorpusId::from_digest(Digest32::from_bytes([3_u8; 32])),
        )
    }

    fn dummy_artifact(byte: u8) -> (ArtifactId, SourceLocatorHash) {
        (
            ArtifactId::from_digest(Digest32::from_bytes([byte; 32])),
            SourceLocatorHash::from_digest(Digest32::from_bytes([byte ^ 0xFF; 32])),
        )
    }

    #[test]
    fn fresh_ledger_runs_in_wal_mode() {
        let tmp = TempDir::new().expect("temp dir");
        let path = tmp.path().join("ledger.sqlite3");
        let (pid, rid, cid) = dummy_ids();
        let ledger =
            Ledger::create_new(&path, "test", &pid, &rid, &cid).expect("create new ledger");
        let mode: String = ledger
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("query journal_mode");
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn batched_transaction_atomically_commits_state_transitions() {
        let tmp = TempDir::new().expect("temp dir");
        let path = tmp.path().join("ledger.sqlite3");
        let (pid, rid, cid) = dummy_ids();
        let mut ledger =
            Ledger::create_new(&path, "test", &pid, &rid, &cid).expect("create new ledger");

        let (aid, slh) = dummy_artifact(0xAA);
        {
            let tx = ledger.transaction().expect("open tx");
            tx.upsert_discovered(&aid, &slh, 42, "FILE.TXT")
                .expect("discovered");
            tx.mark_extracted(&aid, "extract.text.v1", "deadbeef")
                .expect("extracted");
            tx.mark_transformed(&aid).expect("transformed");
            tx.mark_verified(&aid, "abcd1234").expect("verified");
            tx.commit().expect("commit");
        }

        let summary = ledger.artifact_summary(&aid).expect("read").expect("row");
        assert_eq!(summary.state, ArtifactState::Verified);
        assert_eq!(summary.output_id.as_deref(), Some("abcd1234"));
    }

    #[test]
    fn batched_transaction_rolls_back_on_drop() {
        // Kill-mid-write recovery test: open the ledger, write a row inside a
        // batched transaction, drop the transaction without committing, then
        // observe that the row never lands. WAL mode + same-process Drop
        // simulates the parent-panic-after-write case.
        let tmp = TempDir::new().expect("temp dir");
        let path = tmp.path().join("ledger.sqlite3");
        let (pid, rid, cid) = dummy_ids();
        let mut ledger =
            Ledger::create_new(&path, "test", &pid, &rid, &cid).expect("create new ledger");

        let (committed_id, slh_committed) = dummy_artifact(0x11);
        ledger
            .upsert_discovered(&committed_id, &slh_committed, 1, "FILE.TXT")
            .expect("committed write");

        let (uncommitted_id, slh_uncommitted) = dummy_artifact(0x22);
        {
            let tx = ledger.transaction().expect("open tx");
            tx.upsert_discovered(&uncommitted_id, &slh_uncommitted, 2, "FILE.TXT")
                .expect("write inside tx");
            // Drop without commit() — rollback.
        }

        drop(ledger);

        let reopened = Ledger::open_existing(&path).expect("reopen ledger");
        assert!(
            reopened
                .artifact_summary(&committed_id)
                .expect("read committed")
                .is_some(),
            "committed row must survive"
        );
        assert!(
            reopened
                .artifact_summary(&uncommitted_id)
                .expect("read uncommitted")
                .is_none(),
            "uncommitted row must not survive"
        );
    }

    #[test]
    fn proof_tokens_round_trip_preserves_order() {
        let tmp = TempDir::new().expect("temp dir");
        let path = tmp.path().join("ledger.sqlite3");
        let (pid, rid, cid) = dummy_ids();
        let mut ledger =
            Ledger::create_new(&path, "test", &pid, &rid, &cid).expect("create new ledger");
        let (aid, slh) = dummy_artifact(0xCC);
        ledger
            .upsert_discovered(&aid, &slh, 32, "FILE.TXT")
            .expect("discovered");

        let tokens = vec![
            "deadbeef".to_string(),
            "feedface".to_string(),
            "cafebabe".to_string(),
        ];
        ledger
            .replace_proof_tokens(&aid, &tokens)
            .expect("write tokens");

        let read_back = ledger.proof_tokens_for(&aid).expect("read tokens");
        assert_eq!(read_back, tokens, "tokens must round-trip in order");

        // Replacing tokens overwrites the prior list.
        let replacement = vec!["1234".to_string(), "5678".to_string()];
        ledger
            .replace_proof_tokens(&aid, &replacement)
            .expect("replace tokens");
        let after = ledger.proof_tokens_for(&aid).expect("re-read tokens");
        assert_eq!(after, replacement);
    }

    #[test]
    fn proof_tokens_inside_batched_transaction_commit_atomically() {
        let tmp = TempDir::new().expect("temp dir");
        let path = tmp.path().join("ledger.sqlite3");
        let (pid, rid, cid) = dummy_ids();
        let mut ledger =
            Ledger::create_new(&path, "test", &pid, &rid, &cid).expect("create new ledger");
        let (aid, slh) = dummy_artifact(0xDD);
        let tokens = vec!["aa".to_string(), "bb".to_string()];

        {
            let tx = ledger.transaction().expect("open tx");
            tx.upsert_discovered(&aid, &slh, 8, "FILE.TXT")
                .expect("discovered");
            tx.replace_proof_tokens(&aid, &tokens).expect("tokens");
            tx.commit().expect("commit");
        }

        let read = ledger.proof_tokens_for(&aid).expect("read tokens");
        assert_eq!(read, tokens);
    }

    #[test]
    fn open_existing_migrates_v1_ledger_to_v2() {
        // Build a V1-shaped ledger by hand: same DDL as create_new but
        // without the proof_tokens table and with the legacy meta token.
        let tmp = TempDir::new().expect("temp dir");
        let path = tmp.path().join("ledger.sqlite3");
        {
            let conn = Connection::open(&path).expect("open new");
            apply_runtime_pragmas(&conn).expect("pragmas");
            conn.execute_batch(
                r#"
BEGIN;
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY,
  source_locator_hash TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  artifact_type TEXT NOT NULL,
  state TEXT NOT NULL,
  quarantine_reason_code TEXT NULL,
  extractor_id TEXT NULL,
  coverage_hash TEXT NULL,
  output_id TEXT NULL
);

CREATE TABLE IF NOT EXISTS findings_summary (
  artifact_id TEXT NOT NULL,
  class_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  action TEXT NOT NULL,
  count INTEGER NOT NULL,
  FOREIGN KEY (artifact_id) REFERENCES artifacts(artifact_id)
);

CREATE INDEX IF NOT EXISTS artifacts_state_idx ON artifacts(state);
CREATE INDEX IF NOT EXISTS findings_class_id_idx ON findings_summary(class_id);
COMMIT;
"#,
            )
            .expect("v1 schema");
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', 'ledger.v1')",
                [],
            )
            .expect("schema_version");
            for (k, v) in [
                ("tool_version", "test"),
                ("policy_id", "policy"),
                ("run_id", "run"),
                ("input_corpus_id", "corpus"),
            ] {
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                    params![k, v],
                )
                .expect("meta");
            }
        }

        let ledger = Ledger::open_existing(&path).expect("open existing migrates");
        let migrated_version = ledger
            .get_meta("schema_version")
            .expect("read meta")
            .expect("version meta present");
        assert_eq!(migrated_version, LedgerSchemaVersion::V2.as_str());

        // The proof_tokens query must now succeed (returning empty for the
        // v1 ledger which obviously had none).
        let (aid, _slh) = dummy_artifact(0xEE);
        let tokens = ledger.proof_tokens_for(&aid).expect("query");
        assert!(tokens.is_empty());
    }

    #[test]
    fn findings_summary_pk_rejects_duplicate_unmediated_inserts() {
        let tmp = TempDir::new().expect("temp dir");
        let path = tmp.path().join("ledger.sqlite3");
        let (pid, rid, cid) = dummy_ids();
        let mut ledger =
            Ledger::create_new(&path, "test", &pid, &rid, &cid).expect("create new ledger");
        let (aid, slh) = dummy_artifact(0x33);
        ledger
            .upsert_discovered(&aid, &slh, 10, "FILE.TXT")
            .expect("discovered");
        ledger
            .replace_findings_summary(
                &aid,
                &[FindingsSummaryRow {
                    class_id: "PII.A",
                    severity: "HIGH",
                    action: "REDACT",
                    count: 1,
                }],
            )
            .expect("first summary");
        // A direct second INSERT (no DELETE) must be rejected by the PK.
        let raw = ledger.conn.execute(
            "INSERT INTO findings_summary (artifact_id, class_id, severity, action, count) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![aid.to_string(), "PII.A", "HIGH", "REDACT", 1_i64],
        );
        assert!(raw.is_err(), "PK constraint must reject duplicate row");
    }
}
