#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    ContentText,
    StructuredFields,
    Metadata,
    EmbeddedObjects,
    Attachments,
}

impl Surface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContentText => "content_text",
            Self::StructuredFields => "structured_fields",
            Self::Metadata => "metadata",
            Self::EmbeddedObjects => "embedded_objects",
            Self::Attachments => "attachments",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageStatus {
    Full,
    None,
    Unknown,
}

impl CoverageStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::None => "NONE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageMapV1 {
    pub content_text: CoverageStatus,
    pub structured_fields: CoverageStatus,
    pub metadata: CoverageStatus,
    pub embedded_objects: CoverageStatus,
    pub attachments: CoverageStatus,
}

impl CoverageMapV1 {
    pub const fn has_unknown(self) -> bool {
        matches!(
            (
                self.content_text,
                self.structured_fields,
                self.metadata,
                self.embedded_objects,
                self.attachments
            ),
            (CoverageStatus::Unknown, _, _, _, _)
                | (_, CoverageStatus::Unknown, _, _, _)
                | (_, _, CoverageStatus::Unknown, _, _)
                | (_, _, _, CoverageStatus::Unknown, _)
                | (_, _, _, _, CoverageStatus::Unknown)
        )
    }
}
