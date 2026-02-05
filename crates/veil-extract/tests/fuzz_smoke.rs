use std::io::{Cursor, Write};

use veil_domain::{
    ArchiveLimits, QuarantineReasonCode, hash_artifact_id, hash_source_locator_hash,
};
use veil_extract::{ArtifactContext, ExtractOutcome, ExtractorRegistry};
use zip::write::FileOptions;

fn ctx() -> (veil_domain::ArtifactId, veil_domain::SourceLocatorHash) {
    let artifact_id = hash_artifact_id(b"test");
    let source_locator_hash = hash_source_locator_hash("test.bin");
    (artifact_id, source_locator_hash)
}

#[derive(Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn gen_len(&mut self, max: usize) -> usize {
        if max == 0 {
            return 0;
        }
        (self.next_u64() as usize) % max
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = self.next_u64().to_le_bytes();
            let n = (buf.len() - i).min(v.len());
            buf[i..i + n].copy_from_slice(&v[..n]);
            i += n;
        }
    }
}

fn make_zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::<u8>::new());
    let mut writer = zip::ZipWriter::new(cursor);

    let options = FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in entries {
        writer.start_file(*name, options).expect("start zip file");
        writer.write_all(data).expect("write zip data");
    }

    let cursor = writer.finish().expect("finish zip");
    cursor.into_inner()
}

fn make_tar_bytes(path: &str, data: &[u8]) -> Vec<u8> {
    // Minimal ustar tar with one regular file entry.
    assert!(path.as_bytes().len() <= 100);

    let mut header = [0_u8; 512];
    header[..path.len()].copy_from_slice(path.as_bytes());

    fn write_octal(dst: &mut [u8], value: u64) {
        let width = dst.len() - 1;
        let s = format!("{value:0width$o}");
        dst[..width].copy_from_slice(s.as_bytes());
        dst[width] = 0;
    }

    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], data.len() as u64);
    write_octal(&mut header[136..148], 0);

    // checksum field treated as spaces for calculation
    for b in &mut header[148..156] {
        *b = b' ';
    }

    header[156] = b'0'; // regular file
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    let checksum: u64 = header.iter().map(|b| *b as u64).sum();
    // 6 digits, NUL, space
    let chk = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(chk.as_bytes());

    let mut out = Vec::<u8>::new();
    out.extend_from_slice(&header);
    out.extend_from_slice(data);

    let pad = (512 - (data.len() % 512)) % 512;
    out.extend(std::iter::repeat(0_u8).take(pad));
    // two zero blocks
    out.extend(std::iter::repeat(0_u8).take(1024));
    out
}

#[test]
fn extractors_do_not_panic_on_random_bytes() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let types = [
        "TEXT", "CSV", "TSV", "JSON", "NDJSON", "ZIP", "TAR", "EML", "MBOX", "DOCX", "PPTX", "XLSX",
    ];

    let mut rng = XorShift64::new(0xC0FFEE);
    for _ in 0..250 {
        let len = rng.gen_len(8192);
        let mut bytes = vec![0_u8; len];
        rng.fill_bytes(&mut bytes);

        for ty in types {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                reg.extract_by_type(ty, ctx, &bytes)
            }));
            assert!(res.is_ok(), "extractor panicked for type={ty} len={len}");
        }
    }
}

#[test]
fn archive_path_traversal_is_quarantined() {
    let reg = ExtractorRegistry::default();
    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let zip_bytes = make_zip_bytes(&[("../evil.txt", b"hello")]);
    let out = reg.extract_by_type("ZIP", ctx, &zip_bytes);
    let ExtractOutcome::Quarantined { reason, .. } = out else {
        panic!("expected quarantine");
    };
    assert_eq!(reason, QuarantineReasonCode::UnsafePath);

    let tar_bytes = make_tar_bytes("../evil.txt", b"hello");
    let out = reg.extract_by_type("TAR", ctx, &tar_bytes);
    let ExtractOutcome::Quarantined { reason, .. } = out else {
        panic!("expected quarantine");
    };
    assert_eq!(reason, QuarantineReasonCode::UnsafePath);
}

#[test]
fn archive_limits_are_enforced() {
    let mut limits = ArchiveLimits::default();
    limits.max_entries_per_archive = 1;
    let reg = ExtractorRegistry::new(limits);

    let (artifact_id, source_locator_hash) = ctx();
    let ctx = ArtifactContext {
        artifact_id: &artifact_id,
        source_locator_hash: &source_locator_hash,
    };

    let zip_bytes = make_zip_bytes(&[("a.txt", b"hello"), ("b.txt", b"world")]);
    let out = reg.extract_by_type("ZIP", ctx, &zip_bytes);
    let ExtractOutcome::Quarantined { reason, .. } = out else {
        panic!("expected quarantine");
    };
    assert_eq!(reason, QuarantineReasonCode::LimitExceeded);
}
