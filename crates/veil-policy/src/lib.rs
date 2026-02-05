pub mod bundle_id;

use std::collections::BTreeSet;
use std::path::Path;

use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use veil_domain::{PolicyId, Severity};

pub use bundle_id::{PolicyBundleIdError, compute_policy_id};

pub const POLICY_SCHEMA_V1: &str = "policy.v1";

const REGEX_DFA_SIZE_LIMIT_BYTES: usize = 2 * 1024 * 1024;
const REGEX_SIZE_LIMIT_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug)]
pub enum PolicyLoadError {
    Io,
    InvalidJson,
    InvalidSchemaVersion,
    InvalidPolicy(String),
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub policy_id: PolicyId,
    pub classes: Vec<PolicyClass>,
}

#[derive(Debug, Clone)]
pub struct PolicyClass {
    pub class_id: String,
    pub severity: Severity,
    pub detectors: Vec<CompiledDetector>,
    pub action: Action,
    pub field_selector: Option<FieldSelector>,
}

#[derive(Debug, Clone)]
pub enum CompiledDetector {
    Regex(Regex),
    ChecksumLuhn,
}

#[derive(Debug, Clone)]
pub enum Action {
    Redact,
    Mask { keep_last: u32 },
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldSelectorKind {
    JsonPointer,
    CsvHeader,
}

#[derive(Debug, Clone)]
pub struct FieldSelector {
    pub kind: FieldSelectorKind,
    pub fields: Vec<String>,
}

pub fn load_policy_bundle(policy_dir: &Path) -> Result<Policy, PolicyLoadError> {
    let policy_id = compute_policy_id(policy_dir).map_err(|_| PolicyLoadError::Io)?;

    let policy_json_path = policy_dir.join("policy.json");
    let policy_json =
        std::fs::read_to_string(&policy_json_path).map_err(|_| PolicyLoadError::Io)?;

    let parsed: PolicyFileV1 =
        serde_json::from_str(&policy_json).map_err(|_| PolicyLoadError::InvalidJson)?;

    let PolicyFileV1 {
        schema_version,
        classes: parsed_classes,
        defaults,
        scopes,
    } = parsed;

    if schema_version != POLICY_SCHEMA_V1 {
        return Err(PolicyLoadError::InvalidSchemaVersion);
    }

    if let Some(severity) = defaults.severity.as_deref() {
        let _ = parse_severity(severity)?;
    }
    if let Some(action) = defaults.action {
        let _ = compile_action(action)?;
    }

    if !scopes.is_empty() {
        return Err(PolicyLoadError::InvalidPolicy(
            "scopes are not supported in v1 baseline".to_string(),
        ));
    }

    if parsed_classes.is_empty() {
        return Err(PolicyLoadError::InvalidPolicy(
            "policy must define at least one class".to_string(),
        ));
    }

    let mut seen = BTreeSet::<String>::new();
    let mut classes = Vec::<PolicyClass>::new();
    for c in parsed_classes {
        if c.class_id.trim().is_empty() {
            return Err(PolicyLoadError::InvalidPolicy(
                "class_id must be non-empty".to_string(),
            ));
        }
        if !seen.insert(c.class_id.clone()) {
            return Err(PolicyLoadError::InvalidPolicy(format!(
                "duplicate class_id: {}",
                c.class_id
            )));
        }

        let severity = parse_severity(&c.severity)?;

        let (field_selector, detectors) = compile_detectors(c.detectors)?;
        let action = compile_action(c.action)?;

        if detectors.is_empty() {
            return Err(PolicyLoadError::InvalidPolicy(format!(
                "class {} must define at least one detector",
                c.class_id
            )));
        }

        classes.push(PolicyClass {
            class_id: c.class_id,
            severity,
            detectors,
            action,
            field_selector,
        });
    }

    // Deterministic class order for downstream processing.
    classes.sort_by(|a, b| a.class_id.cmp(&b.class_id));

    Ok(Policy { policy_id, classes })
}

fn parse_severity(raw: &str) -> Result<Severity, PolicyLoadError> {
    match raw {
        "LOW" => Ok(Severity::Low),
        "MEDIUM" => Ok(Severity::Medium),
        "HIGH" => Ok(Severity::High),
        _ => Err(PolicyLoadError::InvalidPolicy(
            "severity must be one of LOW/MEDIUM/HIGH".to_string(),
        )),
    }
}

fn compile_detectors(
    detectors: Vec<DetectorFileV1>,
) -> Result<(Option<FieldSelector>, Vec<CompiledDetector>), PolicyLoadError> {
    let mut field_selector = None::<FieldSelector>;
    let mut compiled = Vec::<CompiledDetector>::new();

    for d in detectors {
        match d {
            DetectorFileV1::Regex {
                pattern,
                case_insensitive,
                dot_matches_new_line,
            } => {
                let mut builder = RegexBuilder::new(&pattern);
                builder
                    .size_limit(REGEX_SIZE_LIMIT_BYTES)
                    .dfa_size_limit(REGEX_DFA_SIZE_LIMIT_BYTES)
                    .case_insensitive(case_insensitive)
                    .dot_matches_new_line(dot_matches_new_line);
                let re = builder.build().map_err(|_| {
                    PolicyLoadError::InvalidPolicy("invalid regex pattern".to_string())
                })?;
                compiled.push(CompiledDetector::Regex(re));
            }
            DetectorFileV1::Checksum { algorithm } => match algorithm {
                ChecksumAlgorithmFileV1::Luhn => compiled.push(CompiledDetector::ChecksumLuhn),
            },
            DetectorFileV1::FieldSelector { selector, fields } => {
                if fields.is_empty() {
                    return Err(PolicyLoadError::InvalidPolicy(
                        "field_selector fields must be non-empty".to_string(),
                    ));
                }
                if field_selector.is_some() {
                    return Err(PolicyLoadError::InvalidPolicy(
                        "only one field_selector is allowed per class".to_string(),
                    ));
                }
                let kind = match selector {
                    FieldSelectorKindFileV1::JsonPointer => FieldSelectorKind::JsonPointer,
                    FieldSelectorKindFileV1::CsvHeader => FieldSelectorKind::CsvHeader,
                };
                field_selector = Some(FieldSelector { kind, fields });
            }
        }
    }

    Ok((field_selector, compiled))
}

fn compile_action(action: ActionFileV1) -> Result<Action, PolicyLoadError> {
    match action {
        ActionFileV1::Redact => Ok(Action::Redact),
        ActionFileV1::Mask { keep_last } => {
            if keep_last == 0 {
                return Err(PolicyLoadError::InvalidPolicy(
                    "MASK keep_last must be >= 1".to_string(),
                ));
            }
            Ok(Action::Mask { keep_last })
        }
        ActionFileV1::Drop => Ok(Action::Drop),
        ActionFileV1::Tokenize => Err(PolicyLoadError::InvalidPolicy(
            "TOKENIZE is not supported in v1 baseline".to_string(),
        )),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFileV1 {
    schema_version: String,
    classes: Vec<ClassFileV1>,
    defaults: DefaultsFileV1,
    scopes: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultsFileV1 {
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    action: Option<ActionFileV1>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassFileV1 {
    class_id: String,
    severity: String,
    detectors: Vec<DetectorFileV1>,
    action: ActionFileV1,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum DetectorFileV1 {
    #[serde(rename = "regex")]
    Regex {
        pattern: String,
        #[serde(default)]
        case_insensitive: bool,
        #[serde(default)]
        dot_matches_new_line: bool,
    },
    #[serde(rename = "checksum")]
    Checksum { algorithm: ChecksumAlgorithmFileV1 },
    #[serde(rename = "field_selector")]
    FieldSelector {
        selector: FieldSelectorKindFileV1,
        fields: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChecksumAlgorithmFileV1 {
    Luhn,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FieldSelectorKindFileV1 {
    JsonPointer,
    CsvHeader,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum ActionFileV1 {
    #[serde(rename = "REDACT")]
    Redact,
    #[serde(rename = "MASK")]
    Mask { keep_last: u32 },
    #[serde(rename = "DROP")]
    Drop,
    #[serde(rename = "TOKENIZE")]
    Tokenize,
}
