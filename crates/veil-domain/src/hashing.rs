use blake3::Hasher;

use crate::{
    ArtifactId, ArtifactSortKey, Digest32, InputCorpusId, OutputId, PolicyId, RunId,
    SourceLocatorHash,
};

pub fn hash_artifact_id(original_bytes: &[u8]) -> ArtifactId {
    ArtifactId::from_digest(hash_digest32(original_bytes))
}

pub fn hash_output_id(sanitized_bytes: &[u8]) -> OutputId {
    OutputId::from_digest(hash_digest32(sanitized_bytes))
}

pub fn hash_source_locator_hash(normalized_relative_path: &str) -> SourceLocatorHash {
    SourceLocatorHash::from_digest(hash_digest32(normalized_relative_path.as_bytes()))
}

pub fn compute_input_corpus_id(artifacts: &mut [ArtifactSortKey]) -> InputCorpusId {
    artifacts.sort();

    let mut hasher = Hasher::new();
    for key in artifacts.iter() {
        hasher.update(key.artifact_id.as_digest().as_bytes());
    }

    InputCorpusId::from_digest(Digest32::from_bytes(*hasher.finalize().as_bytes()))
}

pub fn compute_run_id(
    tool_version: &str,
    policy_id: &PolicyId,
    input_corpus_id: &InputCorpusId,
) -> RunId {
    let mut hasher = Hasher::new();
    hasher.update(tool_version.as_bytes());
    hasher.update(policy_id.as_digest().as_bytes());
    hasher.update(input_corpus_id.as_digest().as_bytes());
    RunId::from_digest(Digest32::from_bytes(*hasher.finalize().as_bytes()))
}

fn hash_digest32(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(*blake3::hash(bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_key_orders_by_artifact_id_then_source_locator_hash() {
        let a1 = ArtifactId::from_digest(Digest32::from_bytes([1_u8; 32]));
        let a2 = ArtifactId::from_digest(Digest32::from_bytes([2_u8; 32]));
        let s1 = SourceLocatorHash::from_digest(Digest32::from_bytes([1_u8; 32]));
        let s2 = SourceLocatorHash::from_digest(Digest32::from_bytes([2_u8; 32]));

        let mut keys = vec![
            ArtifactSortKey::new(a2, s1),
            ArtifactSortKey::new(a1, s2),
            ArtifactSortKey::new(a1, s1),
        ];
        keys.sort();

        assert_eq!(keys[0], ArtifactSortKey::new(a1, s1));
        assert_eq!(keys[1], ArtifactSortKey::new(a1, s2));
        assert_eq!(keys[2], ArtifactSortKey::new(a2, s1));
    }

    #[test]
    fn input_corpus_id_is_order_independent() {
        let a1 = ArtifactId::from_digest(Digest32::from_bytes([1_u8; 32]));
        let a2 = ArtifactId::from_digest(Digest32::from_bytes([2_u8; 32]));
        let s1 = SourceLocatorHash::from_digest(Digest32::from_bytes([10_u8; 32]));
        let s2 = SourceLocatorHash::from_digest(Digest32::from_bytes([20_u8; 32]));

        let mut keys_a = vec![ArtifactSortKey::new(a2, s2), ArtifactSortKey::new(a1, s1)];
        let mut keys_b = vec![ArtifactSortKey::new(a1, s1), ArtifactSortKey::new(a2, s2)];

        let id_a = compute_input_corpus_id(&mut keys_a);
        let id_b = compute_input_corpus_id(&mut keys_b);

        assert_eq!(id_a, id_b);
    }

    #[test]
    fn run_id_changes_when_inputs_change() {
        let tool_v1 = "0.1.0";
        let tool_v2 = "0.2.0";
        let policy_1 = PolicyId::from_digest(Digest32::from_bytes([3_u8; 32]));
        let policy_2 = PolicyId::from_digest(Digest32::from_bytes([4_u8; 32]));
        let corpus = InputCorpusId::from_digest(Digest32::from_bytes([5_u8; 32]));

        let run1 = compute_run_id(tool_v1, &policy_1, &corpus);
        let run2 = compute_run_id(tool_v2, &policy_1, &corpus);
        let run3 = compute_run_id(tool_v1, &policy_2, &corpus);

        assert_ne!(run1, run2);
        assert_ne!(run1, run3);
    }
}
