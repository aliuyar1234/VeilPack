use veil_detect::Finding;
use veil_domain::{QuarantineReasonCode, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationOutcome {
    Verified,
    Quarantined { reason: QuarantineReasonCode },
}

pub fn residual_verify(findings: &[Finding]) -> VerificationOutcome {
    let has_findings = findings.iter().any(|f| {
        matches!(
            f.severity,
            Severity::Low | Severity::Medium | Severity::High
        )
    });
    if has_findings {
        return VerificationOutcome::Quarantined {
            reason: QuarantineReasonCode::VerificationFailed,
        };
    }

    VerificationOutcome::Verified
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_detect::{Finding, FindingLocation};

    fn finding(severity: Severity) -> Finding {
        Finding {
            class_id: "PII.Test".to_string(),
            severity,
            location: FindingLocation::Opaque {
                locator: "text:PII.Test:b0:4".to_string(),
            },
            proof_token: None,
        }
    }

    #[test]
    fn residual_verify_allows_empty_findings() {
        assert_eq!(residual_verify(&[]), VerificationOutcome::Verified);
    }

    #[test]
    fn residual_verify_quarantines_low_findings() {
        assert_eq!(
            residual_verify(&[finding(Severity::Low)]),
            VerificationOutcome::Quarantined {
                reason: QuarantineReasonCode::VerificationFailed,
            }
        );
    }

    #[test]
    fn residual_verify_quarantines_medium_findings() {
        assert_eq!(
            residual_verify(&[finding(Severity::Medium)]),
            VerificationOutcome::Quarantined {
                reason: QuarantineReasonCode::VerificationFailed,
            }
        );
    }

    #[test]
    fn residual_verify_quarantines_high_findings() {
        assert_eq!(
            residual_verify(&[finding(Severity::High)]),
            VerificationOutcome::Quarantined {
                reason: QuarantineReasonCode::VerificationFailed,
            }
        );
    }
}
