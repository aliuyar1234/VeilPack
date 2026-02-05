use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use veil_domain::{
    ArtifactId, ArtifactState, InputCorpusId, PolicyId, QuarantineReasonCode, RunId,
    SourceLocatorHash,
};

pub const LEDGER_SCHEMA_VERSION: &str = "ledger.v1";

#[derive(Debug)]
pub enum LedgerError {
    Io,
    Sql,
    UnsupportedSchema,
    MissingMeta,
}

#[derive(Debug, Clone)]
pub struct ArtifactSummary {
    pub state: ArtifactState,
    pub quarantine_reason_code: Option<String>,
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
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| LedgerError::Sql)?;

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
        .map_err(|_| LedgerError::Sql)?;

        let ledger = Self { conn };
        ledger.set_meta("schema_version", LEDGER_SCHEMA_VERSION)?;
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
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| LedgerError::Sql)?;
        let ledger = Self { conn };
        let schema_version = ledger
            .get_meta("schema_version")?
            .ok_or(LedgerError::MissingMeta)?;
        if schema_version != LEDGER_SCHEMA_VERSION {
            return Err(LedgerError::UnsupportedSchema);
        }
        Ok(ledger)
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

    pub fn artifact_summary(
        &self,
        artifact_id: &ArtifactId,
    ) -> Result<Option<ArtifactSummary>, LedgerError> {
        let mut stmt = self
            .conn
            .prepare("SELECT state, quarantine_reason_code FROM artifacts WHERE artifact_id = ?1")
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
        Ok(Some(ArtifactSummary {
            state,
            quarantine_reason_code,
        }))
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
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    pub fn mark_transformed(&mut self, artifact_id: &ArtifactId) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
        tx.execute(
            r#"
UPDATE artifacts
SET state=?2
WHERE artifact_id=?1 AND state NOT IN ('VERIFIED', 'QUARANTINED')
"#,
            params![artifact_id.to_string(), ArtifactState::Transformed.as_str()],
        )
        .map_err(|_| LedgerError::Sql)?;
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    pub fn mark_verified(
        &mut self,
        artifact_id: &ArtifactId,
        output_id: &str,
    ) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
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
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    pub fn quarantine(
        &mut self,
        artifact_id: &ArtifactId,
        reason: QuarantineReasonCode,
    ) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
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
        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
    }

    pub fn replace_findings_summary(
        &mut self,
        artifact_id: &ArtifactId,
        rows: &[FindingsSummaryRow<'_>],
    ) -> Result<(), LedgerError> {
        let tx = self.conn.transaction().map_err(|_| LedgerError::Sql)?;
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

        tx.commit().map_err(|_| LedgerError::Sql)?;
        Ok(())
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
