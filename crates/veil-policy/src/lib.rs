use veil_domain::PolicyId;

pub const POLICY_SCHEMA_V1: &str = "policy.v1";

#[derive(Debug, Clone)]
pub struct Policy {
    pub policy_id: PolicyId,
}
