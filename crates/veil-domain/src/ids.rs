use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    pub fn from_hex(hex: &str) -> Result<Self, ParseHexError> {
        let bytes = decode_hex_32(hex)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Digest32").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseHexError {
    InvalidLength { expected: usize, actual: usize },
    InvalidByte { index: usize },
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut out = vec![0_u8; bytes.len() * 2];
    for (i, b) in bytes.iter().copied().enumerate() {
        let hi = (b >> 4) as usize;
        let lo = (b & 0x0f) as usize;
        out[i * 2] = HEX[hi];
        out[i * 2 + 1] = HEX[lo];
    }

    // Safety: out is always valid ASCII.
    String::from_utf8(out).expect("hex is utf8")
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], ParseHexError> {
    let actual = hex.len();
    let expected = 64;
    if actual != expected {
        return Err(ParseHexError::InvalidLength { expected, actual });
    }

    let mut bytes = [0_u8; 32];
    let in_bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi =
            decode_nibble(in_bytes[i * 2]).ok_or(ParseHexError::InvalidByte { index: i * 2 })?;
        let lo = decode_nibble(in_bytes[i * 2 + 1])
            .ok_or(ParseHexError::InvalidByte { index: i * 2 + 1 })?;
        bytes[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(bytes)
}

fn decode_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

macro_rules! id_newtype {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Digest32);

        impl $name {
            pub const fn from_digest(digest: Digest32) -> Self {
                Self(digest)
            }

            pub const fn as_digest(&self) -> &Digest32 {
                &self.0
            }

            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.0.to_hex())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

id_newtype!(ArtifactId);
id_newtype!(SourceLocatorHash);
id_newtype!(PolicyId);
id_newtype!(RunId);
id_newtype!(InputCorpusId);
id_newtype!(OutputId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest32_hex_roundtrip() {
        let bytes = [0xAB_u8; 32];
        let digest = Digest32::from_bytes(bytes);
        let encoded = digest.to_hex();
        let decoded = Digest32::from_hex(&encoded).expect("valid hex");

        assert_eq!(digest, decoded);
    }

    #[test]
    fn digest32_from_hex_rejects_wrong_length() {
        let err = Digest32::from_hex("00").unwrap_err();
        assert_eq!(
            err,
            ParseHexError::InvalidLength {
                expected: 64,
                actual: 2
            }
        );
    }
}
