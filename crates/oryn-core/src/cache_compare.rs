//! 与已有缓存比较时不把整个旧文件再次加载到堆中。
use std::io::{self, Read};
use std::path::Path;

pub(crate) fn matches(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let mut file = std::fs::File::open(path)?;
    if file.metadata()?.len() != bytes.len() as u64 {
        return Ok(false);
    }
    matches_reader(&mut file, bytes)
}

fn matches_reader(reader: &mut impl Read, bytes: &[u8]) -> io::Result<bool> {
    let mut buffer = [0u8; 16 * 1024];
    for expected in bytes.chunks(buffer.len()) {
        if let Err(e) = reader.read_exact(&mut buffer[..expected.len()]) {
            return if e.kind() == io::ErrorKind::UnexpectedEof {
                Ok(false)
            } else {
                Err(e)
            };
        }
        if &buffer[..expected.len()] != expected {
            return Ok(false);
        }
    }
    // metadata检查后若文件增长，不能将相同前缀误报为相等。
    loop {
        match reader.read(&mut buffer[..1]) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => return other.map(|n| n == 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cache_comparison_files_equal_mismatch_and_missing() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/cache-compare-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{}.bin", std::process::id()));
        std::fs::write(&path, b"same").unwrap();
        assert!(matches(&path, b"same").unwrap());
        assert!(!matches(&path, b"different length").unwrap());
        assert!(!matches(&path, b"diff").unwrap());
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            matches(&path, b"same").unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn cache_comparison_handles_short_reads_and_changes() {
        struct Short<'a>(&'a [u8]);
        impl Read for Short<'_> {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                let n = b.len().min(self.0.len()).min(7);
                b[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }
        let bytes = vec![0x5a; 40_001];
        assert!(matches_reader(&mut Short(&bytes), &bytes).unwrap());
        assert!(!matches_reader(&mut Short(&bytes[..40_000]), &bytes).unwrap());
        assert!(!matches_reader(&mut Short(&bytes), &bytes[..40_000]).unwrap());
        let mut changed = bytes.clone();
        changed[16_384] ^= 1;
        assert!(!matches_reader(&mut Short(&changed), &bytes).unwrap());
        assert!(matches_reader(&mut Short(&[]), &[]).unwrap());
    }
}
