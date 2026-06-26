# sha256.jq — Pure-jq SHA-256 implementation (no bitwise builtins required)
#
# Public entry points:
#
#   sha256_from_stream(gen) — gen: any generator of byte integers → hex digest
#
# ── Performance characteristics (jq 1.7, measured on WSL2) ──────────────────
#
#   The bottleneck is SHA-256 compression: ~832 bitwise-AND calls per 64-byte
#   block, each costing ~8.8 µs in pure-arithmetic jq.  Timing scales linearly:
#
#     Input (binary)   Base64 chars    Wall time    Blocks
#     ──────────────   ────────────    ─────────    ──────
#         1 KiB            1 368         ~136 ms       16
#        10 KiB           13 656        ~1.25 s       160
#        50 KiB           68 268        ~6.3  s       800
#
#   Rule of thumb: ~136 ms per KiB of binary input.
#
#   Practical thresholds for the intended use case (manifest / config validation):
#     < 200 ms  →  ≤ 1.5 KiB — "feels instant"
#     < 1 s     →  ≤ 7.4 KiB — acceptable for scripts
#     < 3 s     →  ≤ 22 KiB  — borderline for automation
#     > 5 s     →  ≥ 37 KiB  — too slow for interactive use
#
#   Docker / OCI image configs: 400 B – 2 KiB → ~55–275 ms  ✓
#   Manifest JSON files:        1 KiB – 5 KiB → ~136–680 ms ✓
#   Actual layer tarballs:      MiB scale      → minutes     ✗ (use host sha256sum)
#
#   Perf note: σ₀/σ₁/Σ₀/Σ₁ are GF(2)-linear (XOR+rotate only, no AND), enabling
#   precomputed half-word lookups: f(x) = t_hi[x/65536|0] ⊕ t_lo[x%65536].
#   Eight 65536-entry tables reduce band calls by ~27%, yielding ~+16% throughput
#   at 50 KiB.  The drawback: the tables weigh ≈ 5.3 MiB of JSON and add ~79 ms
#   of per-invocation load overhead, making them a net loss below ~5 KiB input.

import "bits" as bits;

# ── SHA-256 round constants K[0..63] ──────────────────────────────────────
# FIPS 180-4 §4.2.2: "These words represent the first thirty-two bits of the
# fractional parts of the cube roots of the first sixty-four prime numbers."

def _sha256_K: [
  1116352408, 1899447441, 3049323471, 3921009573,
   961987163, 1508970993, 2453635748, 2870763221,
  3624381080,  310598401,  607225278, 1426881987,
  1925078388, 2162078206, 2614888103, 3248222580,
  3835390401, 4022224774,  264347078,  604807628,
   770255983, 1249150122, 1555081692, 1996064986,
  2554220882, 2821834349, 2952996808, 3210313671,
  3336571891, 3584528711,  113926993,  338241895,
   666307205,  773529912, 1294757372, 1396182291,
  1695183700, 1986661051, 2177026350, 2456956037,
  2730485921, 2820302411, 3259730800, 3345764771,
  3516065817, 3600352804, 4094571909,  275423344,
   430227734,  506948616,  659060556,  883997877,
   958139571, 1322822218, 1537002063, 1747873779,
  1955562222, 2024104815, 2227730452, 2361852424,
  2428436474, 2756734187, 3204031479, 3329325298
];

# ── Initial hash values H0[0..7] ───────────────────────────────────────────
# FIPS 180-4 §5.3.3: "These words were obtained by taking the first thirty-two
# bits of the fractional parts of the square roots of the first eight prime
# numbers."  sha512_H0 uses the same mathematical source extended to 64 bits:
# sha512_H0[i][0] (the hi-half of each [hi, lo] pair) equals _sha256_H0[i].

def _sha256_H0: [
  1779033703, 3144134277, 1013904242, 2773480762,
  1359893119, 2600822924,  528734635, 1541459225
];

# ── 32-bit word primitives ─────────────────────────────────────────────────
# band, bxor, bits::word_to_hex are provided by bits.jq (imported above as bits::).

# Specialised rotations used by SHA-256 — inlined constants avoid pow(2;n)
# calls, saving ~41% per rotation vs the generic form above.
def _r2:  (. / 4         | floor) + (. % 4         * 1073741824);
def _r6:  (. / 64        | floor) + (. % 64        * 67108864);
def _r7:  (. / 128       | floor) + (. % 128       * 33554432);
def _r11: (. / 2048      | floor) + (. % 2048      * 2097152);
def _r13: (. / 8192      | floor) + (. % 8192      * 524288);
def _r17: (. / 131072    | floor) + (. % 131072    * 32768);
def _r18: (. / 262144    | floor) + (. % 262144    * 16384);
def _r19: (. / 524288    | floor) + (. % 524288    * 8192);
def _r22: (. / 4194304   | floor) + (. % 4194304   * 1024);
def _r25: (. / 33554432  | floor) + (. % 33554432  * 128);

# ── SHA-256 Boolean functions ──────────────────────────────────────────────
# FIPS 180-4 §4.1.2:
#   _ch( x, y, z)  = (x ∧ y) ⊕ (¬x ∧ z)
#   _maj( x, y, z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
#   Σ₀²⁵⁶(x)      = ROTR²(x)  ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
#   Σ₁²⁵⁶(x)      = ROTR⁶(x)  ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
#   σ₀²⁵⁶(x)      = ROTR⁷(x)  ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
#   σ₁²⁵⁶(x)      = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)

# Choice: for each bit, select from f (e=1) or g (e=0).
# The two AND terms are always disjoint, so XOR = plain addition.
def _ch($e; $f; $g): bits::band($e; $f) + bits::band(4294967295 - $e; $g);

# Majority: output bit = majority of a, b, c.
# Formula: a XOR ((a XOR b) AND (a XOR c)) — 4 band calls vs 5 in the
# straightforward (a&b)^(a&c)^(b&c) expansion.
def _maj($a; $b; $c):
  bits::band($a; $b) as $ab | ($a + $b - 2*$ab) as $axb |
  bits::band($a; $c) as $ac | ($a + $c - 2*$ac) as $axc |
  bits::band($axb; $axc) as $x |
  $a + $x - 2 * bits::band($a; $x);

# Uppercase Σ — used in the 64 compression rounds.
# Each is a 3-way XOR of rotations; computed as two sequential 2-way XORs.
def _Sigma0:
  _r2 as $r2 | _r13 as $r13 | _r22 as $r22 |
  bits::band($r2; $r13) as $ab | ($r2 + $r13 - 2*$ab) as $x |
  $x + $r22 - 2 * bits::band($x; $r22);

def _Sigma1:
  _r6 as $r6 | _r11 as $r11 | _r25 as $r25 |
  bits::band($r6; $r11) as $ab | ($r6 + $r11 - 2*$ab) as $x |
  $x + $r25 - 2 * bits::band($x; $r25);

# Lowercase σ — used to extend the message schedule; SHR via integer divide.
def _sigma0:
  _r7 as $r7 | _r18 as $r18 | (. / 8 | floor) as $s |
  bits::band($r7; $r18) as $ab | ($r7 + $r18 - 2*$ab) as $x |
  $x + $s - 2 * bits::band($x; $s);

def _sigma1:
  _r17 as $r17 | _r19 as $r19 | (. / 1024 | floor) as $s |
  bits::band($r17; $r19) as $ab | ($r17 + $r19 - 2*$ab) as $x |
  $x + $s - 2 * bits::band($x; $s);

# ── Message schedule ───────────────────────────────────────────────────────
# FIPS 180-4 §6.2.2 step 1: "Prepare the message schedule, {Wt}:"
#   Wt = Mt^(i)                                                    0 ≤ t ≤ 15
#   Wt = σ₁²⁵⁶(W_{t-2}) + W_{t-7} + σ₀²⁵⁶(W_{t-15}) + W_{t-16}  16 ≤ t ≤ 63

# Callers always have the block as a derived value, never as their natural .
# so this takes it as a $arg rather than via pipe.
def _make_schedule($block):
  # W[0..15]: pack 4 bytes big-endian into each 32-bit word
  [ range(16) as $i |
      ($block[$i * 4    ] * 16777216) +
      ($block[$i * 4 + 1] * 65536)   +
      ($block[$i * 4 + 2] * 256)     +
       $block[$i * 4 + 3]            ] |
  # W[16..63]: extend via σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
  # Single mask at the end: the sum of four 32-bit values is < 2^34 < 2^53.
  reduce range(16; 64) as $i (
    .;
    . as $w |
    . + [(($w[$i-2]|_sigma1) + $w[$i-7] + ($w[$i-15]|_sigma0) + $w[$i-16]) % 4294967296]
  );

# ── Compression function ───────────────────────────────────────────────────
# FIPS 180-4 §6.2.2 steps 3–4: for t = 0 to 63:
#   T₁ = h + Σ₁²⁵⁶(e) + _ch(e,f,g) + Kt²⁵⁶ + Wt
#   T₂ = Σ₀²⁵⁶(a) + _maj(a,b,c)
#   h=g; g=f; f=e; e=d+T₁; d=c; c=b; b=a; a=T₁+T₂          (all mod 2³²)
# Then: H₀^(i) = a+H₀^(i-1), …, H₇^(i) = h+H₇^(i-1)        (all mod 2³²)

# Input (.): [a,b,c,d,e,f,g,h] working variables (initialised from hash state)
# Args: w — 64-word schedule, k — 64 round constants
# Output: [a,b,c,d,e,f,g,h] after 64 rounds
def _compress($ws; $ks):
  reduce range(64) as $i (
    .;
    . as [$a, $b, $c, $d, $e, $f, $g, $h] |
    # T1 = h + Σ1(e) + _ch(e,f,g) + K[i] + W[i]   (sum of ≤5 32-bit values < 2^53)
    (($h + ($e | _Sigma1) + _ch($e; $f; $g) + $ws[$i] + $ks[$i]) % 4294967296) as $T1 |
    # T2 = Σ0(a) + _maj(a,b,c)
    ((($a | _Sigma0) + _maj($a; $b; $c)) % 4294967296) as $T2 |
    # Rotate working variables
    [ ($T1 + $T2) % 4294967296, $a, $b, $c, ($d + $T1) % 4294967296, $e, $f, $g ]
  );

# All three args use $-prefix so each is evaluated once with the calling .
# This avoids the pipe-then-evaluate trap: callers pass .buf and .h as $
# args without piping the block in, so both are resolved against the caller's
# current . (typically the accumulator state object) before the function runs.
def _process_block($block; $h; $k):
  _make_schedule($block) as $w |
  ($h | _compress($w; $k)) as $comp |
  [ range(8) as $i | ($h[$i] + $comp[$i]) % 4294967296 ];

# ── SHA-256 finalisation padding ───────────────────────────────────────────
# FIPS 180-4 §5.1.1: "Suppose that the length of the message, M, is l bits.
# Append the bit '1' to the end of the message, followed by k zero bits, where
# k is the smallest, non-negative solution to the equation
#   l + 1 + k ≡ 448 (mod 512)
# Then append the 64-bit block that is equal to the number l expressed using a
# binary representation."

# Input (.): remaining (unprocessed) byte buffer after streaming
# Arg total_len: TOTAL original message length in bytes (for the length suffix)
#
# Appends: 0x80, zero bytes until total ≡ 56 (mod 64), 64-bit big-endian
# bit-count. Result is always 64 or 128 bytes (one or two final blocks).
def _sha256_final_pad($buf; $total_len):
  ($total_len * 8) as $bits |
  $buf + [128]
    + [ range(((55 - $total_len) % 64 + 64) % 64) | 0 ]
    + [ ($bits / 72057594037927936 | floor) % 256,
        ($bits / 281474976710656   | floor) % 256,
        ($bits / 1099511627776     | floor) % 256,
        ($bits / 4294967296        | floor) % 256,
        ($bits / 16777216          | floor) % 256,
        ($bits / 65536             | floor) % 256,
        ($bits / 256               | floor) % 256,
         $bits % 256 ];

# ── Streaming SHA-256 ──────────────────────────────────────────────────────

# Arg gen: any generator that emits individual byte integers (0–255).
#
# SHA-256 compression happens *while* the generator runs — at most 63 buffered
# bytes exist at any moment, regardless of total input size.  After the
# generator is exhausted the remaining buffer is padded and the final 1–2
# blocks are processed to produce the digest.
def sha256_from_stream(gen):
  _sha256_K as $k |
  # Streaming phase: one byte per reduce step, block processed when buf hits 64
  reduce gen as $byte (
    { h: _sha256_H0, buf: [], len: 0 };
    .buf += [$byte] | .len += 1 |
    if (.buf | length) == 64 then
      _process_block(.buf; .h; $k) as $nh |
      .h = $nh | .buf = []
    else . end
  ) |
  # Finalisation phase: pad the remaining buffer and process 1–2 final blocks
  .h as $H |
  _sha256_final_pad(.buf; .len) |
  . as $padded |
  (length / 64) as $nblocks |
  reduce range($nblocks) as $bi (
    $H;
    _process_block($padded[$bi * 64 : ($bi + 1) * 64]; .; $k)
  ) |
  map(bits::word_to_hex) | join("");
