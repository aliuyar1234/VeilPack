use veil_detect::Finding;
use veil_domain::{QuarantineReasonCode, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationOutcome {
    Verified,
    Quarantined { reason: QuarantineReasonCode },
}

pub fn residual_verify(findings: &[Finding]) -> VerificationOutcome {
    let has_high = findings.iter().any(|f| f.severity == Severity::High);
    if has_high {
        return VerificationOutcome::Quarantined {
            reason: QuarantineReasonCode::VerificationFailed,
        };
    }

    VerificationOutcome::Verified
}
