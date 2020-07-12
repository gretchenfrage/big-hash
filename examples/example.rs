
use std::fmt::{self, Debug, Formatter, Write};
use big_hash::{md5_hash, sha256_hash, sha512_hash};

struct Hex<'a>(&'a [u8]);

impl<'a> Debug for Hex<'a> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        const DIGITS: [u8; 16] = *b"0123456789abcdef";
        for &b in self.0 {
            let i0 = ((b as usize) & 0xf0) >> 8;
            let i1 = (b as usize) & 0x0f;
            f.write_char(DIGITS[i0] as char)?;
            f.write_char(DIGITS[i1] as char)?;
        }
        Ok({})
    }
}

fn main() {
    dbg!(Hex(&sha256_hash(&"hello world")));
    dbg!(Hex(&sha512_hash(&Some([1, 3, 4]))));
    dbg!(md5_hash(&"127.0.0.1".parse::<std::net::Ipv4Addr>().ok()));
}
