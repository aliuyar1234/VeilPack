use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    Discovered,
    Extracted,
    Transformed,
    Verified,
    Quarantined,
}

impl ArtifactState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Verified | Self::Quarantined)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "DISCOVERED",
            Self::Extracted => "EXTRACTED",
            Self::Transformed => "TRANSFORMED",
            Self::Verified => "VERIFIED",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineReasonCode {
    UnsupportedFormat,
    Encrypted,
    ParseError,
    LimitExceeded,
    UnsafePath,
    UnknownCoverage,
    VerificationFailed,
    InternalError,
    PdfEncrypted,
    PdfParseError,
    PdfMalformed,
    PdfOcrRequiredButDisabled,
    PdfOcrFailed,
    PdfRenderFailed,
    PdfUnsupportedSurfacePresent,
    PdfLimitExceeded,
    PdfEmbeddedFileExtractionFailed,
    PdfXfaUnsupported,
    PdfActionsPresentUnsupported,
}

impl QuarantineReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Self::Encrypted => "ENCRYPTED",
            Self::ParseError => "PARSE_ERROR",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::UnsafePath => "UNSAFE_PATH",
            Self::UnknownCoverage => "UNKNOWN_COVERAGE",
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::InternalError => "INTERNAL_ERROR",
            Self::PdfEncrypted => "PDF_ENCRYPTED",
            Self::PdfParseError => "PDF_PARSE_ERROR",
            Self::PdfMalformed => "PDF_MALFORMED",
            Self::PdfOcrRequiredButDisabled => "PDF_OCR_REQUIRED_BUT_DISABLED",
            Self::PdfOcrFailed => "PDF_OCR_FAILED",
            Self::PdfRenderFailed => "PDF_RENDER_FAILED",
            Self::PdfUnsupportedSurfacePresent => "PDF_UNSUPPORTED_SURFACE_PRESENT",
            Self::PdfLimitExceeded => "PDF_LIMIT_EXCEEDED",
            Self::PdfEmbeddedFileExtractionFailed => "PDF_EMBEDDED_FILE_EXTRACTION_FAILED",
            Self::PdfXfaUnsupported => "PDF_XFA_UNSUPPORTED",
            Self::PdfActionsPresentUnsupported => "PDF_ACTIONS_PRESENT_UNSUPPORTED",
        }
    }
}

impl fmt::Display for QuarantineReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}
