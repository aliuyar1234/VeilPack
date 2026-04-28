// Worker IPC v2.
//
// Wire format: little-endian u32 length prefix followed by a CBOR-encoded
// `WorkerEnvelope`. The envelope carries a `protocol_version: u32` as its
// first field so that mismatched parent/child binaries fail closed with a
// stable `worker_protocol_version_mismatch` event code rather than parsing
// past one another.
//
// Why CBOR over JSON: CBOR is length-self-describing, binary-safe (no
// double-encoding required for arbitrary bytes that might appear in
// detector payloads in the future), and round-trips compact integers
// without textual ambiguity. ciborium is already in workspace deps.
//
// Why a length prefix on top of CBOR: the parent reads exactly one
// envelope and stops; without a length prefix the parent would have to
// rely on EOF-on-stdout to bound parsing, which interacts poorly with
// child crash modes (partial writes, signal-killed children leaving
// truncated bytes that nevertheless decode as valid CBOR up to a point).

use crate::error::AppError;
use serde::{Deserialize, Serialize};

pub(crate) const WORKER_PROTOCOL_VERSION: u32 = 2;

/// Hard cap on the size of a single envelope. Worker payloads carry
/// canonical artifacts that have already passed `max_bytes_per_artifact`
/// limits upstream, so 256 MiB is a generous parent-side guard against a
/// rogue child sending an unbounded length prefix.
const MAX_ENVELOPE_BYTES: u32 = 256 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WorkerEnvelope {
    pub(crate) protocol_version: u32,
    pub(crate) body: WorkerBody,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WorkerBody {
    Extracted {
        extractor_id: String,
        canonical: WorkerCanonicalArtifact,
        coverage: WorkerCoverageMap,
    },
    Quarantined {
        extractor_id: Option<String>,
        reason_code: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum WorkerCanonicalArtifact {
    Text {
        text: String,
    },
    Csv {
        delimiter: u8,
        headers: Vec<String>,
        records: Vec<Vec<String>>,
    },
    Json {
        value: serde_json::Value,
    },
    Ndjson {
        values: Vec<serde_json::Value>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct WorkerCoverageMap {
    pub(crate) content_text: String,
    pub(crate) structured_fields: String,
    pub(crate) metadata: String,
    pub(crate) embedded_objects: String,
    pub(crate) attachments: String,
}

pub(crate) fn write_envelope<W: std::io::Write>(
    w: &mut W,
    env: &WorkerEnvelope,
) -> Result<(), AppError> {
    let mut buf = Vec::with_capacity(256);
    ciborium::ser::into_writer(env, &mut buf)
        .map_err(|_| AppError::Internal("worker_serialize_failed".to_string()))?;
    let len = u32::try_from(buf.len())
        .map_err(|_| AppError::Internal("worker_envelope_too_large".to_string()))?;
    if len > MAX_ENVELOPE_BYTES {
        return Err(AppError::Internal("worker_envelope_too_large".to_string()));
    }
    w.write_all(&len.to_le_bytes())
        .map_err(|_| AppError::Internal("worker_write_failed".to_string()))?;
    w.write_all(&buf)
        .map_err(|_| AppError::Internal("worker_write_failed".to_string()))?;
    Ok(())
}

pub(crate) fn read_envelope<R: std::io::Read>(r: &mut R) -> Result<WorkerEnvelope, AppError> {
    let mut len_buf = [0_u8; 4];
    r.read_exact(&mut len_buf)
        .map_err(|_| AppError::Internal("worker_read_failed".to_string()))?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_ENVELOPE_BYTES {
        return Err(AppError::Internal("worker_envelope_too_large".to_string()));
    }
    let mut payload = vec![0_u8; len as usize];
    r.read_exact(&mut payload)
        .map_err(|_| AppError::Internal("worker_read_failed".to_string()))?;
    let env: WorkerEnvelope = ciborium::de::from_reader(payload.as_slice())
        .map_err(|_| AppError::Internal("worker_deserialize_failed".to_string()))?;
    if env.protocol_version != WORKER_PROTOCOL_VERSION {
        tracing::error!(
            event = "worker_protocol_version_mismatch",
            reason_code = "INTERNAL_ERROR",
            expected = WORKER_PROTOCOL_VERSION,
            received = env.protocol_version,
            "extract worker protocol version mismatch"
        );
        return Err(AppError::Internal(
            "worker_protocol_version_mismatch".to_string(),
        ));
    }
    Ok(env)
}

pub(crate) fn extract_outcome_to_worker_envelope(
    outcome: veil_extract::ExtractOutcome,
) -> WorkerEnvelope {
    let body = match outcome {
        veil_extract::ExtractOutcome::Extracted {
            extractor_id,
            canonical,
            coverage,
        } => WorkerBody::Extracted {
            extractor_id: extractor_id.as_str().to_string(),
            canonical: canonical_to_worker(canonical),
            coverage: coverage_to_worker(coverage),
        },
        veil_extract::ExtractOutcome::Quarantined {
            extractor_id,
            reason,
        } => WorkerBody::Quarantined {
            extractor_id: extractor_id.map(|id| id.as_str().to_string()),
            reason_code: reason.as_str().to_string(),
        },
    };
    WorkerEnvelope {
        protocol_version: WORKER_PROTOCOL_VERSION,
        body,
    }
}

pub(crate) fn extract_outcome_from_worker_envelope(
    env: WorkerEnvelope,
) -> Result<veil_extract::ExtractOutcome, AppError> {
    match env.body {
        WorkerBody::Extracted {
            extractor_id,
            canonical,
            coverage,
        } => {
            let extractor_id = veil_extract::ExtractorId::parse(&extractor_id)
                .map_err(|_| AppError::Internal("worker_unknown_extractor_id".to_string()))?;
            let coverage = coverage_from_worker(coverage)
                .ok_or_else(|| AppError::Internal("worker_invalid_coverage".to_string()))?;
            Ok(veil_extract::ExtractOutcome::Extracted {
                extractor_id,
                canonical: canonical_from_worker(canonical),
                coverage,
            })
        }
        WorkerBody::Quarantined {
            extractor_id,
            reason_code,
        } => {
            let reason = quarantine_reason_from_code(&reason_code)
                .ok_or_else(|| AppError::Internal("worker_invalid_reason_code".to_string()))?;
            let extractor_id =
                match extractor_id {
                    Some(v) => Some(veil_extract::ExtractorId::parse(&v).map_err(|_| {
                        AppError::Internal("worker_unknown_extractor_id".to_string())
                    })?),
                    None => None,
                };
            Ok(veil_extract::ExtractOutcome::Quarantined {
                extractor_id,
                reason,
            })
        }
    }
}

pub(crate) fn limit_exceeded_envelope() -> WorkerEnvelope {
    WorkerEnvelope {
        protocol_version: WORKER_PROTOCOL_VERSION,
        body: WorkerBody::Quarantined {
            extractor_id: None,
            reason_code: veil_domain::QuarantineReasonCode::LimitExceeded
                .as_str()
                .to_string(),
        },
    }
}

fn canonical_to_worker(canonical: veil_extract::CanonicalArtifact) -> WorkerCanonicalArtifact {
    match canonical {
        veil_extract::CanonicalArtifact::Text(v) => WorkerCanonicalArtifact::Text {
            text: v.as_str().to_string(),
        },
        veil_extract::CanonicalArtifact::Csv(v) => WorkerCanonicalArtifact::Csv {
            delimiter: v.delimiter,
            headers: v.headers,
            records: v.records,
        },
        veil_extract::CanonicalArtifact::Json(v) => {
            WorkerCanonicalArtifact::Json { value: v.value }
        }
        veil_extract::CanonicalArtifact::Ndjson(v) => {
            WorkerCanonicalArtifact::Ndjson { values: v.values }
        }
    }
}

fn canonical_from_worker(canonical: WorkerCanonicalArtifact) -> veil_extract::CanonicalArtifact {
    match canonical {
        WorkerCanonicalArtifact::Text { text } => {
            veil_extract::CanonicalArtifact::Text(veil_extract::CanonicalText::new(text))
        }
        WorkerCanonicalArtifact::Csv {
            delimiter,
            headers,
            records,
        } => veil_extract::CanonicalArtifact::Csv(veil_extract::CanonicalCsv {
            delimiter,
            headers,
            records,
        }),
        WorkerCanonicalArtifact::Json { value } => {
            veil_extract::CanonicalArtifact::Json(veil_extract::CanonicalJson { value })
        }
        WorkerCanonicalArtifact::Ndjson { values } => {
            veil_extract::CanonicalArtifact::Ndjson(veil_extract::CanonicalNdjson { values })
        }
    }
}

fn coverage_to_worker(coverage: veil_domain::CoverageMapV1) -> WorkerCoverageMap {
    WorkerCoverageMap {
        content_text: coverage.content_text.as_str().to_string(),
        structured_fields: coverage.structured_fields.as_str().to_string(),
        metadata: coverage.metadata.as_str().to_string(),
        embedded_objects: coverage.embedded_objects.as_str().to_string(),
        attachments: coverage.attachments.as_str().to_string(),
    }
}

fn coverage_from_worker(coverage: WorkerCoverageMap) -> Option<veil_domain::CoverageMapV1> {
    Some(veil_domain::CoverageMapV1 {
        content_text: coverage_status_from_wire(&coverage.content_text)?,
        structured_fields: coverage_status_from_wire(&coverage.structured_fields)?,
        metadata: coverage_status_from_wire(&coverage.metadata)?,
        embedded_objects: coverage_status_from_wire(&coverage.embedded_objects)?,
        attachments: coverage_status_from_wire(&coverage.attachments)?,
    })
}

fn coverage_status_from_wire(value: &str) -> Option<veil_domain::CoverageStatus> {
    Some(match value {
        "FULL" => veil_domain::CoverageStatus::Full,
        "NONE" => veil_domain::CoverageStatus::None,
        "UNKNOWN" => veil_domain::CoverageStatus::Unknown,
        _ => return None,
    })
}

fn quarantine_reason_from_code(value: &str) -> Option<veil_domain::QuarantineReasonCode> {
    Some(match value {
        "UNSUPPORTED_FORMAT" => veil_domain::QuarantineReasonCode::UnsupportedFormat,
        "ENCRYPTED" => veil_domain::QuarantineReasonCode::Encrypted,
        "PARSE_ERROR" => veil_domain::QuarantineReasonCode::ParseError,
        "LIMIT_EXCEEDED" => veil_domain::QuarantineReasonCode::LimitExceeded,
        "UNSAFE_PATH" => veil_domain::QuarantineReasonCode::UnsafePath,
        "UNKNOWN_COVERAGE" => veil_domain::QuarantineReasonCode::UnknownCoverage,
        "VERIFICATION_FAILED" => veil_domain::QuarantineReasonCode::VerificationFailed,
        "INTERNAL_ERROR" => veil_domain::QuarantineReasonCode::InternalError,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_domain::{CoverageMapV1, CoverageStatus, QuarantineReasonCode};

    fn extracted_outcome() -> veil_extract::ExtractOutcome {
        veil_extract::ExtractOutcome::Extracted {
            extractor_id: veil_extract::ExtractorId::NdjsonV1,
            canonical: veil_extract::CanonicalArtifact::Ndjson(veil_extract::CanonicalNdjson {
                values: vec![serde_json::json!({ "k": "v" })],
            }),
            coverage: CoverageMapV1 {
                content_text: CoverageStatus::None,
                structured_fields: CoverageStatus::Full,
                metadata: CoverageStatus::Full,
                embedded_objects: CoverageStatus::None,
                attachments: CoverageStatus::None,
            },
        }
    }

    #[test]
    fn extracted_outcome_roundtrips_through_length_prefixed_cbor() {
        let env = extract_outcome_to_worker_envelope(extracted_outcome());
        let mut buf = Vec::<u8>::new();
        write_envelope(&mut buf, &env).expect("write envelope");

        // First four bytes are the length prefix.
        let len_prefix = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(len_prefix as usize, buf.len() - 4);

        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_envelope(&mut cursor).expect("read envelope");
        assert_eq!(decoded.protocol_version, WORKER_PROTOCOL_VERSION);

        let outcome = extract_outcome_from_worker_envelope(decoded).expect("decode outcome");
        match outcome {
            veil_extract::ExtractOutcome::Extracted {
                extractor_id,
                canonical,
                coverage,
            } => {
                assert_eq!(extractor_id, veil_extract::ExtractorId::NdjsonV1);
                assert_eq!(coverage.structured_fields, CoverageStatus::Full);
                let veil_extract::CanonicalArtifact::Ndjson(v) = canonical else {
                    panic!("expected NDJSON canonical payload");
                };
                assert_eq!(v.values, vec![serde_json::json!({ "k": "v" })]);
            }
            _ => panic!("expected extracted outcome"),
        }
    }

    #[test]
    fn quarantined_outcome_roundtrips_through_length_prefixed_cbor() {
        let outcome = veil_extract::ExtractOutcome::Quarantined {
            extractor_id: Some(veil_extract::ExtractorId::ZipV1),
            reason: QuarantineReasonCode::UnsafePath,
        };

        let env = extract_outcome_to_worker_envelope(outcome);
        let mut buf = Vec::<u8>::new();
        write_envelope(&mut buf, &env).expect("write envelope");

        let mut cursor = std::io::Cursor::new(buf);
        let decoded = read_envelope(&mut cursor).expect("read envelope");
        let outcome = extract_outcome_from_worker_envelope(decoded).expect("decode outcome");
        match outcome {
            veil_extract::ExtractOutcome::Quarantined {
                extractor_id,
                reason,
            } => {
                assert_eq!(extractor_id, Some(veil_extract::ExtractorId::ZipV1));
                assert_eq!(reason, QuarantineReasonCode::UnsafePath);
            }
            _ => panic!("expected quarantined outcome"),
        }
    }

    #[test]
    fn wrong_protocol_version_is_rejected() {
        let stale = WorkerEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION + 1,
            body: WorkerBody::Quarantined {
                extractor_id: None,
                reason_code: "UNSAFE_PATH".to_string(),
            },
        };
        let mut buf = Vec::<u8>::new();
        write_envelope(&mut buf, &stale).expect("write envelope");

        let mut cursor = std::io::Cursor::new(buf);
        let err = read_envelope(&mut cursor).expect_err("must reject mismatched protocol version");
        match err {
            AppError::Internal(label) => {
                assert_eq!(label, "worker_protocol_version_mismatch");
            }
            _ => panic!("expected internal error variant"),
        }
    }

    #[test]
    fn invalid_extractor_id_is_rejected() {
        let env = WorkerEnvelope {
            protocol_version: WORKER_PROTOCOL_VERSION,
            body: WorkerBody::Quarantined {
                extractor_id: Some("extract.unknown.v1".to_string()),
                reason_code: "UNSAFE_PATH".to_string(),
            },
        };
        let err = extract_outcome_from_worker_envelope(env).expect_err("invalid extractor");
        match err {
            AppError::Internal(label) => assert_eq!(label, "worker_unknown_extractor_id"),
            _ => panic!("expected internal error variant"),
        }
    }
}
