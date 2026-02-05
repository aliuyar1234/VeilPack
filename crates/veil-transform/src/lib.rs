use veil_detect::Finding;
use veil_domain::QuarantineReasonCode;
use veil_extract::CanonicalText;
use veil_policy::Policy;

#[derive(Debug, Clone)]
pub enum TransformOutcome {
    Transformed { sanitized_bytes: Vec<u8> },
    Quarantined { reason: QuarantineReasonCode },
}

pub trait Transformer {
    fn transform(
        &self,
        policy: &Policy,
        canonical: &CanonicalText,
        findings: &[Finding],
    ) -> TransformOutcome;
}
