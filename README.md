# md5hash

This crate provides no_std compatible MD5 hashing without dependencies, written in safe Rust.

The crate consists of a [`MD5Hasher`] type which takes in data using the [digest] method and then hashes it using
the MD5 algorithm. Once all the data has been "digested" using the [digest] method the [finish] method returns a [`MD5Digest`] type representing
the result of the hash.

### Examples

A MD5Hasher instance can be created and [digest] can be called repeatedly for disjointed slices.
```rust
use md5hash::MD5Hasher;

let mut hasher = MD5Hasher::new();
hasher.digest(&"message");
hasher.digest(&" ");
hasher.digest(&"digest");           // f96b697d7cb7938d525a2f31aaf161d0
assert_eq!(hasher.finish().as_ref(), &[0xf9,0x6b,0x69,0x7d,0x7c,0xb7,0x93,0x8d,
                                       0x52,0x5a,0x2f,0x31,0xaa,0xf1,0x61,0xd0]);
```

Or the [hash] function can be used as a convenience function to hash a single slice.
```rust
use md5hash::MD5Hasher;

assert_eq!(MD5Hasher::hash(&"message digest").as_ref(), // f96b697d7cb7938d525a2f31aaf161d0
    &[0xf9,0x6b,0x69,0x7d,0x7c,0xb7,0x93,0x8d,
      0x52,0x5a,0x2f,0x31,0xaa,0xf1,0x61,0xd0]);
```

### Security
MD5 is a broken hashing algorithm, and should not be used for anything that requires any kind of security.
It is also not recommended to be used for new systems even if security is not a concern.
Instead this hash should only be used for situations that requires specifically MD5, such as legacy systems.

[finish]: MD5Hasher::finish
[digest]: MD5Hasher::digest
[hash]: MD5Hasher::hash
