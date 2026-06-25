# jq-unhinged

`jq` is a JSON processor.  Implementing SHA-256, BLAKE3, and gzip decompression in it is, strictly speaking, unhinged.

Pure-`jq` streaming base64 decoder, SHA-256/SHA-512/BLAKE3 implementations, and gzip decompressor.
No shell utilities, no external dependencies -- just `jq`. 🥳

All byte streams are represented as generators of raw integers (0–255), making them safe for arbitrary binary data.
Unlike `jq`'s built-in `@base64d` -- which decodes to a UTF-8 string and silently mangles bytes above 127 -- these handle the full 0–255 range correctly. 👀

All files are designed to be `include`d in your own `jq` programs.
Point `jq` at the directory containing these files with `-L /path/to/dir`, or `-L .` when running from the repo root.

---

## [`b64.jq`](b64.jq)

### `b64_stream_decode`

```console
$ jq -r -L . 'include "b64"; [b64_stream_decode] | implode' <<< '"SGVsbG8sIHdvcmxkIQ=="'
Hello, world!
$ # important note on this example: jq's "implode" expects an array of unicode codepoints and this returns an array of bytes, so this will lead to mojibake like "café" -> "cafÃ©"
```

### `b64_stream_encode(gen)` / `b64_stream_encode(gen; wrap)`

Encode a stream of byte integers to base64.  `wrap=0` (the default) emits a single string; any positive integer wraps at exactly that many characters per line, matching `base64 -w`.

```console
$ jq -rn -L . 'include "b64"; "SGVsbG8sIHdvcmxkIQ==" | b64_stream_encode(b64_stream_decode)'
SGVsbG8sIHdvcmxkIQ==
$ jq -rn -L . 'include "b64"; "Zm9vCg==" | b64_stream_encode(b64_stream_decode; 3)'
Zm9
vCg
==
$ base64 -w3 <<< 'foo'
Zm9
vCg
==
```

---

## [`sha256.jq`](sha256.jq)

### `sha256_from_stream(gen)`

```console
$ jq -rn -L . 'include "b64"; include "sha256"; sha256_from_stream("SGVsbG8sIHdvcmxkIQ==" | b64_stream_decode)'
315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
$ base64 -d <<< 'SGVsbG8sIHdvcmxkIQ==' | sha256sum
315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3  -

$ jq -rn -L . 'include "b64"; include "sha256"; "hell yeah 🤘\n" | @base64 | sha256_from_stream(b64_stream_decode)'
2c77828134a0c3b2f8786d1e961585db6a6a746ac3af03ab363c5c1cf3af8ec9
$ sha256sum <<< 'hell yeah 🤘'
2c77828134a0c3b2f8786d1e961585db6a6a746ac3af03ab363c5c1cf3af8ec9  -
```

---

## [`sha512.jq`](sha512.jq)

### `sha512_from_stream(gen)`

```console
$ jq -rn -L . 'include "b64"; include "sha512"; sha512_from_stream("SGVsbG8sIHdvcmxkIQ==" | b64_stream_decode)'
c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421
$ base64 -d <<< 'SGVsbG8sIHdvcmxkIQ==' | sha512sum
c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421  -
```

---

## [`blake3.jq`](blake3.jq)

BLAKE3 uses a binary Merkle tree over 1024-byte chunks and supports variable-length output (XOF).

### `blake3_from_stream(gen)`

```console
$ jq -rn -L . 'include "b64"; include "blake3"; blake3_from_stream("SGVsbG8sIHdvcmxkIQ==" | b64_stream_decode)'
ede5c0b10f2ec4979c69b52f61e42ff5b413519ce09be0f14d098dcfe5f6f98d
```

---

## [`gzip.jq`](gzip.jq)

Pure-`jq` gzip decompressor implementing RFC 1952 (gzip wrapper) and RFC 1951 (DEFLATE).
Handles all three DEFLATE block types: stored (type 00), fixed Huffman (type 01), and dynamic Huffman (type 10).

The decompressor is a streaming state machine: it consumes one compressed byte per iteration and emits
decompressed bytes immediately, keeping only the DEFLATE sliding window (≤ 32 768 bytes) in memory.
The gzip CRC32 footer is consumed but not verified.

### `gzip_from_stream(gen)`

Takes a generator of compressed byte integers and emits decompressed byte integers.
Composes naturally with `b64_stream_decode` and the hash functions:

```console
$ jq -rn -L . 'include "b64"; include "sha256"; include "gzip"; "H4sIAAAAAAAAA/NIzcnJ11Eozy/KSVEEAObG5usNAAAA" | sha256_from_stream(gzip_from_stream(b64_stream_decode))'
315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3
$ printf 'Hello, world!' | sha256sum
315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3  -
```

---

## Authorship

This code was written using "claude my eyes right out" as an implementation vehicle, under close direction from Tianon at every step -- including algorithm choices, `jq` idioms, and design decisions.
The creative direction and domain expertise throughout are Tianon's.
