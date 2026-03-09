use serde::{Deserialize, Serialize};

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
    content_text: String,
    structured_fields: String,
    metadata: String,
    embedded_objects: String,
    attachments: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum ExtractWorkerResponse {
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

pub(crate) fn extract_outcome_to_worker_response(
    outcome: veil_extract::ExtractOutcome,
) -> ExtractWorkerResponse {
    match outcome {
        veil_extract::ExtractOutcome::Extracted {
            extractor_id,
            canonical,
            coverage,
        } => ExtractWorkerResponse::Extracted {
            extractor_id: extractor_id.to_string(),
            canonical: canonical_to_worker(canonical),
            coverage: coverage_to_worker(coverage),
        },
        veil_extract::ExtractOutcome::Quarantined {
            extractor_id,
            reason,
        } => ExtractWorkerResponse::Quarantined {
            extractor_id: extractor_id.map(str::to_string),
            reason_code: reason.as_str().to_string(),
        },
    }
}

pub(crate) fn extract_outcome_from_worker_response(
    response: ExtractWorkerResponse,
) -> Result<veil_extract::ExtractOutcome, String> {
    match response {
        ExtractWorkerResponse::Extracted {
            extractor_id,
            canonical,
            coverage,
        } => {
            let extractor_id = extractor_id_from_wire(&extractor_id)
                .ok_or_else(|| "worker returned unknown extractor_id (redacted)".to_string())?;
            let coverage = coverage_from_worker(coverage)
                .ok_or_else(|| "worker returned invalid coverage payload (redacted)".to_string())?;
            Ok(veil_extract::ExtractOutcome::Extracted {
                extractor_id,
                canonical: canonical_from_worker(canonical),
                coverage,
            })
        }
        ExtractWorkerResponse::Quarantined {
            extractor_id,
            reason_code,
        } => {
            let reason = quarantine_reason_from_code(&reason_code)
                .ok_or_else(|| "worker returned invalid reason_code (redacted)".to_string())?;
            let extractor_id = match extractor_id {
                Some(v) => Some(extractor_id_from_wire(&v).ok_or_else(|| {
                    "worker returned unknown extractor_id (redacted)".to_string()
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

pub(crate) fn limit_exceeded_response() -> ExtractWorkerResponse {
    ExtractWorkerResponse::Quarantined {
        extractor_id: None,
        reason_code: veil_domain::QuarantineReasonCode::LimitExceeded
            .as_str()
            .to_string(),
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

fn extractor_id_from_wire(value: &str) -> Option<&'static str> {
    Some(match value {
        "extract.text.v1" => "extract.text.v1",
        "extract.csv.v1" => "extract.csv.v1",
        "extract.tsv.v1" => "extract.tsv.v1",
        "extract.json.v1" => "extract.json.v1",
        "extract.ndjson.v1" => "extract.ndjson.v1",
        "extract.zip.v1" => "extract.zip.v1",
        "extract.tar.v1" => "extract.tar.v1",
        "extract.eml.v1" => "extract.eml.v1",
        "extract.mbox.v1" => "extract.mbox.v1",
        "extract.ooxml.docx.v1" => "extract.ooxml.docx.v1",
        "extract.ooxml.pptx.v1" => "extract.ooxml.pptx.v1",
        "extract.ooxml.xlsx.v1" => "extract.ooxml.xlsx.v1",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ExtractWorkerResponse, extract_outcome_from_worker_response,
        extract_outcome_to_worker_response,
    };
    use veil_domain::{CoverageMapV1, CoverageStatus, QuarantineReasonCode};

    #[test]
    fn extracted_outcome_roundtrips_through_worker_wire() {
        let outcome = veil_extract::ExtractOutcome::Extracted {
            extractor_id: "extract.ndjson.v1",
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
        };

        let response = extract_outcome_to_worker_response(outcome);
        let roundtripped =
            extract_outcome_from_worker_response(response).expect("worker roundtrip");

        match roundtripped {
            veil_extract::ExtractOutcome::Extracted {
                extractor_id,
                canonical,
                coverage,
            } => {
                assert_eq!(extractor_id, "extract.ndjson.v1");
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
    fn quarantined_outcome_roundtrips_through_worker_wire() {
        let outcome = veil_extract::ExtractOutcome::Quarantined {
            extractor_id: Some("extract.zip.v1"),
            reason: QuarantineReasonCode::UnsafePath,
        };

        let response = extract_outcome_to_worker_response(outcome);
        let roundtripped =
            extract_outcome_from_worker_response(response).expect("worker roundtrip");

        match roundtripped {
            veil_extract::ExtractOutcome::Quarantined {
                extractor_id,
                reason,
            } => {
                assert_eq!(extractor_id, Some("extract.zip.v1"));
                assert_eq!(reason, QuarantineReasonCode::UnsafePath);
            }
            _ => panic!("expected quarantined outcome"),
        }
    }

    #[test]
    fn invalid_extractor_id_is_rejected() {
        let response = ExtractWorkerResponse::Quarantined {
            extractor_id: Some("extract.unknown.v1".to_string()),
            reason_code: "UNSAFE_PATH".to_string(),
        };

        let err = extract_outcome_from_worker_response(response).expect_err("invalid extractor");
        assert!(err.contains("unknown extractor_id"));
    }
}
