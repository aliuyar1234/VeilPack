#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenizationScope {
    PerRun,
}

impl TokenizationScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerRun => "PER_RUN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    pub max_nested_archive_depth: u32,
    pub max_entries_per_archive: u32,
    pub max_expansion_ratio: u32,
    pub max_expanded_bytes_per_archive: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_nested_archive_depth: 3,
            max_entries_per_archive: 100_000,
            max_expansion_ratio: 25,
            max_expanded_bytes_per_archive: 50 * 1024 * 1024 * 1024,
        }
    }
}
