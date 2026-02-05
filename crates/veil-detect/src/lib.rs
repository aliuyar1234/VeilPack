use veil_domain::Severity;
use veil_extract::CanonicalText;
use veil_policy::Policy;

#[derive(Debug, Clone)]
pub struct Finding {
    pub class_id: String,
    pub severity: Severity,
    pub location: FindingLocation,
    pub proof_token: Option<String>,
}

#[derive(Debug, Clone)]
pub enum FindingLocation {
    Opaque { locator: String },
}

pub trait DetectorEngine {
    fn detect(&self, policy: &Policy, canonical: &CanonicalText) -> Vec<Finding>;
}
