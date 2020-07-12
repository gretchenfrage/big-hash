# Big Hash

Compute MD5, SHA256, and SHA512 hashes of data through the `std::hash` 
API.

## Be warned that:

- `std::hash` implementations are not necessarily consistent 
  cross-platform, for example, they may use native-endianness,
  or be dependent on implementation details of things like 
  `OsString`.
- [MD5 should be considered cryptographically broken and unsuitable
  for cryptographic use.][1]

[1]: https://github.com/stainless-steel/md5#security-warning

## Features

The `hash-md5`, `hash-sha256`, and `hash-sha512` features toggle the 
compilation of their respective hashing utilities.


## No-std Support

This crate does not depend on the stdlib, and will always compile
in no-std mode.
