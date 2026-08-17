use std::fmt::Write as _;

use sha2::{Digest, Sha256};

const SHA256_HEX_LENGTH: usize = 64;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(SHA256_HEX_LENGTH);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

pub fn matches_sha256(bytes: &[u8], expected: &str) -> bool {
    if expected.len() != SHA256_HEX_LENGTH {
        return false;
    }

    let actual = sha256_hex(bytes);
    constant_time_eq(actual.as_bytes(), expected.as_bytes())
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_compares_sha256() {
        let digest = sha256_hex(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(matches_sha256(b"abc", &digest));
        assert!(!matches_sha256(b"changed", &digest));
        assert!(!matches_sha256(b"abc", "not-a-digest"));
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"diff"));
        assert!(!constant_time_eq(b"same", b"short"));
    }
}
