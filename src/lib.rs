//! Compute MD5, SHA256, and SHA512 hashes of data through the `core::hash` 
//! API.
//! 
//! ## Be warned that:
//!
//! - `core::hash` implementations are not necessarily consistent 
//!   cross-platform, for example, they may use native-endianness,
//!   or be dependent on implementation details of things like 
//!   `OsString`.
//! - [MD5 should be considered cryptographically broken and unsuitable
//!   for cryptographic use.][1]
//!
//! [1]: https://github.com/stainless-steel/md5#security-warning

#![no_std]

use core::{
    hash::{Hash, Hasher},
    convert::TryFrom,
};

/// Compute an MD5 digest through the `core::hash` API.
///
/// # Security Warning
/// 
/// MD5 should be considered cryptographically broken and unsuitable
/// for cryptographic use. 
#[cfg(feature = "hash-md5")]
pub fn md5_hash<H: Hash>(data: &H) -> [u8; 16] {
    let mut hasher = md5_hasher::Md5Hasher::new();
    data.hash(&mut hasher);
    hasher.digest()
}

#[cfg(feature = "hash-md5")]
#[doc(opaque)]
pub use md5_hasher::Md5Hasher;

/// Compute an SHA256 hash through the `core::hash` API.
#[cfg(feature = "hash-sha256")]
pub fn sha256_hash<H: Hash>(data: &H) -> [u8; 32] {
    let mut hasher = sha256_hasher::Sha256Hasher::new();
    data.hash(&mut hasher);
    hasher.finalize()
}

#[cfg(feature = "hash-sha256")]
#[doc(opaque)]
pub use sha256_hasher::Sha256Hasher;

/// Compute an SHA512 hash through the `core::hash` API.
#[cfg(feature = "hash-sha512")]
pub fn sha512_hash<H: Hash>(data: &H) -> [u8; 64] {
    let mut hasher = sha512_hasher::Sha512Hasher::new();
    data.hash(&mut hasher);
    hasher.finalize()
}

#[cfg(feature = "hash-sha512")]
#[doc(opaque)]
pub use sha512_hasher::Sha512Hasher;

/// Input size must be a multiple of 8.
fn bytes_xor_u64(slice: &[u8]) -> u64 {
    assert_eq!(slice.len() % 8, 0);

    let mut accum: u64 = 0;
    for i in 0..slice.len() / 8 {
        let subslice = &slice[i * 8..(i + 1) * 8];
        let subslice = <[u8; 8]>::try_from(subslice).unwrap();
        accum ^= u64::from_ne_bytes(subslice);
    }

    accum
}

#[cfg(feature = "hash-md5")]
mod md5_hasher {
    extern crate md5;
    use super::*;

    /// Glue between `core::hash` and `md5`.
    #[derive(Clone)]
    pub struct Md5Hasher(md5::Context);

    impl Md5Hasher {
        pub fn new() -> Self {
            Md5Hasher(md5::Context::new())
        }

        /// Digest the data into an MD5 hash.
        pub fn digest(&self) -> [u8; 16] {
            self.0.clone().compute().into()
        }
    }

    impl Hasher for Md5Hasher {
        fn finish(&self) -> u64 {
            bytes_xor_u64(&self.digest())
        }

        fn write(&mut self, bytes: &[u8]) {
            self.0.consume(bytes);
        }
    }
}

#[cfg(feature = "hash-sha256")]
mod sha256_hasher {
    extern crate hmac_sha256;

    use super::*;
    use hmac_sha256 as sha256;

    /// Glue between `core::hash` and `hmac_sha256`.
    #[derive(Copy, Clone)]
    pub struct Sha256Hasher(sha256::Hash);

    impl Sha256Hasher {
        pub fn new() -> Self {
            Sha256Hasher(sha256::Hash::new())
        }

        /// Compute the SHA256 hash.
        pub fn finalize(&self) -> [u8; 32] {
            self.0.finalize()
        }
    }

    impl Hasher for Sha256Hasher {
        fn finish(&self) -> u64 {
            bytes_xor_u64(&self.finalize())
        }

        fn write(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }
    }
}

#[cfg(feature = "hash-sha512")]
mod sha512_hasher {
    extern crate hmac_sha512;

    use super::*;
    use hmac_sha512 as sha512;

    /// Glue between `core::hash` and `hmac_sha512`.
    #[derive(Copy, Clone)]
    pub struct Sha512Hasher(sha512::Hash);

    impl Sha512Hasher {
        pub fn new() -> Self {
            Sha512Hasher(sha512::Hash::new())
        }

        /// Compute the SHA512 hash.
        pub fn finalize(&self) -> [u8; 64] {
            self.0.finalize()
        }
    }

    impl Hasher for Sha512Hasher {
        fn finish(&self) -> u64 {
            bytes_xor_u64(&self.finalize())
        }

        fn write(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }
    }
}

