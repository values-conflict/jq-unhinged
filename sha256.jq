# sha256.jq — Pure-jq SHA-256 implementation (no bitwise builtins required)
#
# Public entry points:
#
#   sha256_of_b64         — input (.): base64 string → 64-char lowercase hex digest
#   sha256_of_bytes       — input (.): array of byte integers (0–255) → hex digest
#   sha256_from_stream(gen) — gen: any generator of byte integers → hex digest
#
# Base64 decoding is handled by b64.jq (included below).
#
# Include in other scripts with:
#   include "sha256";        # if sha256.jq is on the jq search path
#   include "/path/sha256";  # explicit path, no .jq extension in the string

include "b64";

# ── SHA-256 round constants K[0..63] ──────────────────────────────────────
# First 32 bits of the fractional parts of the cube roots of primes 2..311

def sha256_K: [
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
# First 32 bits of the fractional parts of the square roots of primes 2..19

def sha256_H0: [
  1779033703, 3144134277, 1013904242, 2773480762,
  1359893119, 2600822924,  528734635, 1541459225
];

# ── Bitwise primitives (pure arithmetic — no builtins needed) ──────────────
#
# Core identity:  bxor(a,b) = a + b − 2·band(a,b)
#                 bor(a,b)  = a + b −   band(a,b)
#                 bnot32(x) = 4294967295 − x
#
# Only band needs real bit-level logic.  We use a 256-entry nibble lookup
# table (indexed by a_nibble*16 + b_nibble) to process 4 bits at a time —
# 8 lookups cover all 32 bits with no reduce loop.

# Nibble AND table: T[a*16+b] = a AND b  for a, b in 0..15
def _nat: [
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,
  0,0,2,2,0,0,2,2,0,0,2,2,0,0,2,2,
  0,1,2,3,0,1,2,3,0,1,2,3,0,1,2,3,
  0,0,0,0,4,4,4,4,0,0,0,0,4,4,4,4,
  0,1,0,1,4,5,4,5,0,1,0,1,4,5,4,5,
  0,0,2,2,4,4,6,6,0,0,2,2,4,4,6,6,
  0,1,2,3,4,5,6,7,0,1,2,3,4,5,6,7,
  0,0,0,0,0,0,0,0,8,8,8,8,8,8,8,8,
  0,1,0,1,0,1,0,1,8,9,8,9,8,9,8,9,
  0,0,2,2,0,0,2,2,8,8,10,10,8,8,10,10,
  0,1,2,3,0,1,2,3,8,9,10,11,8,9,10,11,
  0,0,0,0,4,4,4,4,8,8,8,8,12,12,12,12,
  0,1,0,1,4,5,4,5,8,9,8,9,12,13,12,13,
  0,0,2,2,4,4,6,6,8,8,10,10,12,12,14,14,
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
];

# 32-bit AND: 8 nibble lookups, no loops
def band(a; b):
  _nat as $t |
  $t[ (a         % 16) * 16 + (b         % 16) ]            +
  $t[ ((a/16     |floor)%16) * 16 + ((b/16     |floor)%16) ] * 16       +
  $t[ ((a/256    |floor)%16) * 16 + ((b/256    |floor)%16) ] * 256      +
  $t[ ((a/4096   |floor)%16) * 16 + ((b/4096   |floor)%16) ] * 4096     +
  $t[ ((a/65536  |floor)%16) * 16 + ((b/65536  |floor)%16) ] * 65536    +
  $t[ ((a/1048576|floor)%16) * 16 + ((b/1048576|floor)%16) ] * 1048576  +
  $t[ ((a/16777216 |floor)%16)*16 + ((b/16777216 |floor)%16)] * 16777216 +
  $t[ (a/268435456|floor)    * 16 +  (b/268435456|floor)    ] * 268435456;

# 32-bit XOR via arithmetic identity: a XOR b = a + b - 2*(a AND b)
def bxor(a; b): band(a; b) as $ab | a + b - 2 * $ab;

# 32-bit NOT: complement relative to 0xFFFFFFFF
def bnot32: 4294967295 - .;

# ── 32-bit word primitives ─────────────────────────────────────────────────

# Mask to 32 bits (jq numbers are IEEE 754 doubles, exact to 2^53)
def mask32: . % 4294967296;

# Modular 32-bit addition
def add32(b): (. + b) % 4294967296;

# Right-rotate a 32-bit word by n positions.
# The two halves are always disjoint, so their OR = their sum.
def rotr32(n):
  (. / pow(2; n) | floor) + ((. % pow(2; n)) * pow(2; 32 - n));

# ── SHA-256 Boolean functions ──────────────────────────────────────────────

# Choice: for each bit, select from f (e=1) or g (e=0).
# The two AND terms are always disjoint, so XOR = plain addition.
def Ch(e; f; g): band(e; f) + band(4294967295 - e; g);

# Majority: output bit = majority of a, b, c.
# bxor via arithmetic: p XOR q = p + q - 2*(p AND q)
def Maj(a; b; c):
  band(a; b) as $ab | band(a; c) as $ac | band(b; c) as $bc |
  ($ab + $ac - 2 * band($ab; $ac)) as $t |
  $t + $bc - 2 * band($t; $bc);

# Uppercase Σ — used in the 64 compression rounds
# Each is a 3-way XOR of rotations; computed as two sequential 2-way XORs.
def Sigma0:
  rotr32(2) as $r2 | rotr32(13) as $r13 | rotr32(22) as $r22 |
  band($r2; $r13) as $ab | ($r2 + $r13 - 2*$ab) as $x |
  $x + $r22 - 2 * band($x; $r22);

def Sigma1:
  rotr32(6) as $r6 | rotr32(11) as $r11 | rotr32(25) as $r25 |
  band($r6; $r11) as $ab | ($r6 + $r11 - 2*$ab) as $x |
  $x + $r25 - 2 * band($x; $r25);

# Lowercase σ — used to extend the message schedule; SHR via integer divide
def sigma0:
  rotr32(7) as $r7 | rotr32(18) as $r18 | (. / 8 | floor) as $s |
  band($r7; $r18) as $ab | ($r7 + $r18 - 2*$ab) as $x |
  $x + $s - 2 * band($x; $s);

def sigma1:
  rotr32(17) as $r17 | rotr32(19) as $r19 | (. / 1024 | floor) as $s |
  band($r17; $r19) as $ab | ($r17 + $r19 - 2*$ab) as $x |
  $x + $s - 2 * band($x; $s);

# ── Message schedule ───────────────────────────────────────────────────────

# Callers always have the block as a derived value, never as their natural .
# so this takes it as a $arg rather than via pipe.
def make_schedule($block):
  # W[0..15]: pack 4 bytes big-endian into each 32-bit word
  [ range(16) as $i |
      ($block[$i * 4    ] * 16777216) +
      ($block[$i * 4 + 1] * 65536)   +
      ($block[$i * 4 + 2] * 256)     +
       $block[$i * 4 + 3]            ] |
  # W[16..63]: extend via σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
  reduce range(16; 64) as $i (
    .;
    . as $w |
    . + [ ($w[$i -  2] | sigma1) |
          add32($w[$i -  7])     |
          add32($w[$i - 15] | sigma0) |
          add32($w[$i - 16]) ]
  );

# ── Compression function ───────────────────────────────────────────────────

# Input (.): [a,b,c,d,e,f,g,h] working variables (initialised from hash state)
# Args: w — 64-word schedule, k — 64 round constants
# Output: [a,b,c,d,e,f,g,h] after 64 rounds
def compress($ws; $ks):
  reduce range(64) as $i (
    .;
    .[0] as $a | .[1] as $b | .[2] as $c | .[3] as $d |
    .[4] as $e | .[5] as $f | .[6] as $g | .[7] as $h |
    # T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]   (sum of ≤5 32-bit values < 2^53)
    (($h + ($e | Sigma1) + Ch($e; $f; $g) + $ws[$i] + $ks[$i]) % 4294967296) as $T1 |
    # T2 = Σ0(a) + Maj(a,b,c)
    ((($a | Sigma0) + Maj($a; $b; $c)) % 4294967296) as $T2 |
    # Rotate working variables
    [ ($T1 + $T2) % 4294967296, $a, $b, $c, ($d + $T1) % 4294967296, $e, $f, $g ]
  );

# All three args use $-prefix so each is evaluated once with the calling .
# This avoids the pipe-then-evaluate trap: callers pass .buf and .h as $
# args without piping the block in, so both are resolved against the caller's
# current . (typically the accumulator state object) before the function runs.
def process_block($block; $h; $k):
  make_schedule($block) as $w |
  ($h | compress($w; $k)) as $comp |
  [ range(8) as $i | ($h[$i] + $comp[$i]) % 4294967296 ];

# ── SHA-256 finalisation padding ───────────────────────────────────────────

# Input (.): remaining (unprocessed) byte buffer after streaming
# Arg total_len: TOTAL original message length in bytes (for the length suffix)
#
# Appends: 0x80, zero bytes until total ≡ 56 (mod 64), 64-bit big-endian
# bit-count. Result is always 64 or 128 bytes (one or two final blocks).
def sha256_final_pad($buf; $total_len):
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

# ── Hex formatting ─────────────────────────────────────────────────────────

# Convert a 32-bit word to an 8-character lowercase hex string
def word_to_hex:
  ("0123456789abcdef" | explode) as $hex |
  [268435456, 16777216, 1048576, 65536, 4096, 256, 16, 1] as $pows |
  [ range(8) as $i | $hex[(. / $pows[$i] | floor) % 16] ] |
  implode;

# ── Streaming SHA-256 ──────────────────────────────────────────────────────

# Arg gen: any generator that emits individual byte integers (0–255).
#
# SHA-256 compression happens *while* the generator runs — at most 63 buffered
# bytes exist at any moment, regardless of total input size.  After the
# generator is exhausted the remaining buffer is padded and the final 1–2
# blocks are processed to produce the digest.
def sha256_from_stream(gen):
  sha256_K as $k |
  # Streaming phase: one byte per reduce step, block processed when buf hits 64
  reduce gen as $byte (
    { h: sha256_H0, buf: [], len: 0 };
    .buf += [$byte] | .len += 1 |
    if (.buf | length) == 64 then
      process_block(.buf; .h; $k) as $nh |
      .h = $nh | .buf = []
    else . end
  ) |
  # Finalisation phase: pad the remaining buffer and process 1–2 final blocks
  .h as $H |
  sha256_final_pad(.buf; .len) |
  . as $padded |
  (length / 64) as $nblocks |
  reduce range($nblocks) as $bi (
    $H;
    process_block($padded[$bi * 64 : ($bi + 1) * 64]; .; $k)
  ) |
  map(word_to_hex) | join("");

# ── Public convenience entry points ───────────────────────────────────────

# Input (.): base64-encoded string (standard alphabet, "=" padding)
# Output: 64-character lowercase hex SHA-256 digest of the decoded bytes
def sha256_of_b64:
  sha256_from_stream(b64_stream_decode);

# Input (.): array of byte integers (0–255)
# Output: 64-character lowercase hex SHA-256 digest
def sha256_of_bytes:
  sha256_from_stream(.[]);
