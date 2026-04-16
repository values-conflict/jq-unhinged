# sha512.jq — Pure-jq SHA-512 implementation (no bitwise builtins required)
#
# Public entry points:
#
#   sha512_of_b64         — input (.): base64 string → 128-char lowercase hex digest
#   sha512_of_bytes       — input (.): array of byte integers (0–255) → hex digest
#   sha512_from_stream(gen) — gen: any generator of byte integers → hex digest
#
# Base64 decoding is handled by b64.jq (included below).
# Shared bitwise primitives (_nat, band, bxor, bnot32, word_to_hex) come from
# bits.jq (included below); sha256.jq and sha512.jq share these without duplication.
#
# ── 64-bit arithmetic via [hi, lo] pairs ────────────────────────────────────
#
# jq numbers are IEEE 754 doubles, exact for integers up to 2^53.  SHA-512
# uses 64-bit (uint64) values that can reach 2^64 − 1, so plain jq numbers
# cannot hold them.  Every 64-bit word is therefore stored as [hi, lo] — two
# 32-bit halves — keeping all intermediate values below 2^32 < 2^53.
#
#   add64([ah,al]; [bh,bl]):  carry from lo into hi via division; hi sum fits
#                              in 33 bits (≤ 2^32−1 + 2^32−1 + 1 = 2^33−1 < 2^53)
#
#   ROTR64(n) for n < 32:   cross-half arithmetic, no swap needed
#   ROTR64(n) for n ≥ 32:   ROTR64(n−32) on [lo, hi]  (swap halves first)
#   SHR64(n)  for n < 32:   high half is just h>>n; low gets cross-carry from h
#
# ── Performance characteristics (jq 1.7, measured on WSL2) ─────────────────
#
#   SHA-512 uses ~2 112 band calls per 128-byte block vs SHA-256's 832 per
#   64-byte block.  The [hi,lo] pair arithmetic adds modest overhead per call.
#   Measured wall time (null-byte inputs, medians over 3 runs):
#
#     Input (binary)   Base64 chars    Blocks   Wall time    vs sha256.jq
#     ──────────────   ────────────    ──────   ─────────    ────────────
#         1 KiB            1 368            8     ~207 ms        ×1.41
#        10 KiB           13 656           80     ~1.84 s        ×1.36
#        50 KiB           68 268          400     ~9.2  s        ×1.36
#
#   Rule of thumb: ~207 ms per KiB of binary input (~1.4× sha256.jq).
#   The ratio is lower than naive band-count ratios predict because b64 decode
#   overhead is shared and constant across both algorithms.
#
#   Practical thresholds for the intended use case (manifest / config validation):
#     < 200 ms  →  ≤ ~1 KiB  — "feels instant"
#     < 1 s     →  ≤ ~5 KiB  — acceptable for scripts
#     < 3 s     →  ≤ ~14 KiB — borderline for automation
#     > 5 s     →  ≥ ~24 KiB — too slow for interactive use
#
#   Docker / OCI image configs: 400 B – 2 KiB →  ~85–415 ms  ✓
#   Manifest JSON files:        1 KiB – 5 KiB →  ~210 ms–1 s ✓
#   Actual layer tarballs:      MiB scale      →  minutes     ✗ (use host sha512sum)

include "bits";
include "b64";

# ── SHA-512 round constants K[0..79] ─────────────────────────────────────────
# First 64 bits of the fractional parts of the cube roots of primes 2..409.
# Each constant is [hi, lo] (two 32-bit halves of the 64-bit value).
# K[0..63] hi-halves match sha256_K exactly (same mathematical source, more bits).

def sha512_K: [
  [1116352408, 3609767458], [1899447441,  602891725], [3049323471, 3964484399], [3921009573, 2173295548],
  [ 961987163, 4081628472], [1508970993, 3053834265], [2453635748, 2937671579], [2870763221, 3664609560],
  [3624381080, 2734883394], [ 310598401, 1164996542], [ 607225278, 1323610764], [1426881987, 3590304994],
  [1925078388, 4068182383], [2162078206,  991336113], [2614888103,  633803317], [3248222580, 3479774868],
  [3835390401, 2666613458], [4022224774,  944711139], [ 264347078, 2341262773], [ 604807628, 2007800933],
  [ 770255983, 1495990901], [1249150122, 1856431235], [1555081692, 3175218132], [1996064986, 2198950837],
  [2554220882, 3999719339], [2821834349,  766784016], [2952996808, 2566594879], [3210313671, 3203337956],
  [3336571891, 1034457026], [3584528711, 2466948901], [ 113926993, 3758326383], [ 338241895,  168717936],
  [ 666307205, 1188179964], [ 773529912, 1546045734], [1294757372, 1522805485], [1396182291, 2643833823],
  [1695183700, 2343527390], [1986661051, 1014477480], [2177026350, 1206759142], [2456956037,  344077627],
  [2730485921, 1290863460], [2820302411, 3158454273], [3259730800, 3505952657], [3345764771,  106217008],
  [3516065817, 3606008344], [3600352804, 1432725776], [4094571909, 1467031594], [ 275423344,  851169720],
  [ 430227734, 3100823752], [ 506948616, 1363258195], [ 659060556, 3750685593], [ 883997877, 3785050280],
  [ 958139571, 3318307427], [1322822218, 3812723403], [1537002063, 2003034995], [1747873779, 3602036899],
  [1955562222, 1575990012], [2024104815, 1125592928], [2227730452, 2716904306], [2361852424,  442776044],
  [2428436474,  593698344], [2756734187, 3733110249], [3204031479, 2999351573], [3329325298, 3815920427],
  [3391569614, 3928383900], [3515267271,  566280711], [3940187606, 3454069534], [4118630271, 4000239992],
  [ 116418474, 1914138554], [ 174292421, 2731055270], [ 289380356, 3203993006], [ 460393269,  320620315],
  [ 685471733,  587496836], [ 852142971, 1086792851], [1017036298,  365543100], [1126000580, 2618297676],
  [1288033470, 3409855158], [1501505948, 4234509866], [1607167915,  987167468], [1816402316, 1246189591]
];

# ── Initial hash values H0[0..7] ──────────────────────────────────────────────
# First 64 bits of the fractional parts of the square roots of primes 2..19.
# H0[i] hi-halves match sha256_H0 exactly (same source, more bits).

def sha512_H0: [
  [1779033703, 4089235720],
  [3144134277, 2227873595],
  [1013904242, 4271175723],
  [2773480762, 1595750129],
  [1359893119, 2917565137],
  [2600822924,  725511199],
  [ 528734635, 4215389547],
  [1541459225,  327033209]
];

# ── 64-bit operations built on the 32-bit band/bxor/bnot32 from bits.jq ──────
#
# jq does not support array destructuring in function parameter lists
# (def f([a,b]) is a compile error).  All [hi,lo] destructuring is done
# inside each function body via "$arg as [$h, $l]" bindings instead.

# 64-bit AND: apply 32-bit band to each half independently.
def band64($a; $b):
  $a as [$ah, $al] | $b as [$bh, $bl] |
  [band($ah;$bh), band($al;$bl)];

# 64-bit XOR: same arithmetic identity as bxor, applied per-half.
def bxor64($a; $b):
  $a as [$ah, $al] | $b as [$bh, $bl] |
  band($ah; $bh) as $h | band($al; $bl) as $l |
  [ $ah + $bh - 2*$h, $al + $bl - 2*$l ];

# 64-bit NOT: complement each 32-bit half.
def bnot64: [ 4294967295 - .[0], 4294967295 - .[1] ];

# 64-bit modular addition with carry.
# lo sum fits in 33 bits (≤ 2^33−1 < 2^53); carry is 0 or 1.
# hi sum ≤ 2^32−1 + 2^32−1 + 1 = 2^33−1 < 2^53 — safe before the final mask.
def add64($a; $b):
  $a as [$ah, $al] | $b as [$bh, $bl] |
  ($al + $bl) as $s |
  [ ($ah + $bh + ($s / 4294967296 | floor)) % 4294967296, $s % 4294967296 ];

# 64-bit word → 16-character lowercase hex string.
def word64_to_hex: (.[0] | word_to_hex) + (.[1] | word_to_hex);

# ── Specialised 64-bit rotations and shifts ───────────────────────────────────
#
# For ROTR64(n) with 0 < n < 32, on [h, l]:
#   new_h = (h >> n) | (l << 32−n)  =  (h / 2^n | floor) + (l % 2^n * 2^(32−n))
#   new_l = (l >> n) | (h << 32−n)  =  (l / 2^n | floor) + (h % 2^n * 2^(32−n))
#
# For ROTR64(n) with n ≥ 32:  ROTR64(n) = ROTR64(n−32) on [lo, hi]
#   (swap the halves, then apply the n−32 < 32 formula with lo/hi exchanged)
#
# For SHR64(n) with 0 < n < 32:
#   new_h = h >> n               =  h / 2^n | floor
#   new_l = (l >> n) | (h << 32−n) = (l / 2^n | floor) + (h % 2^n * 2^(32−n))
#
# Inline constants avoid pow(2;n) calls (~41% savings per rotation, same as sha256.jq).
# sigma0_64 uses: ROTR1, ROTR8, SHR7
# sigma1_64 uses: ROTR19, ROTR61, SHR6
# Sigma0_64 uses: ROTR28, ROTR34, ROTR39
# Sigma1_64 uses: ROTR14, ROTR18, ROTR41

def _r64_1:  .[0] as $h | .[1] as $l |
  [ ($h/2|floor)         + ($l%2         * 2147483648),
    ($l/2|floor)         + ($h%2         * 2147483648) ];

def _r64_8:  .[0] as $h | .[1] as $l |
  [ ($h/256|floor)       + ($l%256       * 16777216),
    ($l/256|floor)       + ($h%256       * 16777216) ];

def _s64_7:  .[0] as $h | .[1] as $l |            # SHR64(7)
  [ ($h/128|floor),
    ($l/128|floor)       + ($h%128       * 33554432) ];

def _r64_14: .[0] as $h | .[1] as $l |
  [ ($h/16384|floor)     + ($l%16384     * 262144),
    ($l/16384|floor)     + ($h%16384     * 262144) ];

def _r64_18: .[0] as $h | .[1] as $l |
  [ ($h/262144|floor)    + ($l%262144    * 16384),
    ($l/262144|floor)    + ($h%262144    * 16384) ];

def _r64_19: .[0] as $h | .[1] as $l |
  [ ($h/524288|floor)    + ($l%524288    * 8192),
    ($l/524288|floor)    + ($h%524288    * 8192) ];

def _r64_28: .[0] as $h | .[1] as $l |
  [ ($h/268435456|floor) + ($l%268435456 * 16),
    ($l/268435456|floor) + ($h%268435456 * 16) ];

def _r64_34: .[0] as $h | .[1] as $l |            # ROTR64(32+2): swap then ROTR(2)
  [ ($l/4|floor)         + ($h%4         * 1073741824),
    ($h/4|floor)         + ($l%4         * 1073741824) ];

def _r64_39: .[0] as $h | .[1] as $l |            # ROTR64(32+7): swap then ROTR(7)
  [ ($l/128|floor)       + ($h%128       * 33554432),
    ($h/128|floor)       + ($l%128       * 33554432) ];

def _r64_41: .[0] as $h | .[1] as $l |            # ROTR64(32+9): swap then ROTR(9)
  [ ($l/512|floor)       + ($h%512       * 8388608),
    ($h/512|floor)       + ($l%512       * 8388608) ];

def _r64_61: .[0] as $h | .[1] as $l |            # ROTR64(32+29): swap then ROTR(29)
  [ ($l/536870912|floor) + ($h%536870912 * 8),
    ($h/536870912|floor) + ($l%536870912 * 8) ];

def _s64_6:  .[0] as $h | .[1] as $l |            # SHR64(6)
  [ ($h/64|floor),
    ($l/64|floor)        + ($h%64        * 67108864) ];

# ── SHA-512 Boolean functions ─────────────────────────────────────────────────

# Choice: for each bit, select from f (e=1) or g (e=0).
# The two AND terms are always disjoint (e AND NOT(e) = 0), so XOR = addition.
# Applied independently to each 32-bit half — 4 band calls total (vs 2 for SHA-256).
def Ch64($e; $f; $g):
  $e as [$eh, $el] | $f as [$fh, $fl] | $g as [$gh, $gl] |
  [ band($eh; $fh) + band(4294967295 - $eh; $gh),
    band($el; $fl) + band(4294967295 - $el; $gl) ];

# Majority: output bit = majority of a, b, c.
# Formula: a XOR ((a XOR b) AND (a XOR c)) — applied per half.
# 8 band calls total (vs 4 for SHA-256).
def Maj64($a; $b; $c):
  $a as [$ah, $al] | $b as [$bh, $bl] | $c as [$ch, $cl] |
  band($ah; $bh) as $abh | ($ah + $bh - 2*$abh) as $axbh |
  band($al; $bl) as $abl | ($al + $bl - 2*$abl) as $axbl |
  band($ah; $ch) as $ach | ($ah + $ch - 2*$ach) as $axch |
  band($al; $cl) as $acl | ($al + $cl - 2*$acl) as $axcl |
  band($axbh; $axch) as $andh | band($axbl; $axcl) as $andl |
  band($ah; $andh) as $fabh | band($al; $andl) as $fabl |
  [ $ah + $andh - 2*$fabh, $al + $andl - 2*$fabl ];

# Uppercase Σ — used in compression rounds.
# Each is a 3-way XOR of rotations; computed as two sequential 2-way XORs.
# 4 band calls total per Sigma (vs 2 for SHA-256).
def Sigma0_64:
  (_r64_28) as $r28 | (_r64_34) as $r34 | (_r64_39) as $r39 |
  bxor64($r28; $r34) as $x |
  bxor64($x; $r39);

def Sigma1_64:
  (_r64_14) as $r14 | (_r64_18) as $r18 | (_r64_41) as $r41 |
  bxor64($r14; $r18) as $x |
  bxor64($x; $r41);

# Lowercase σ — used to extend the message schedule.
# Third operation is SHR (not ROTR); SHR via integer divide on the high half.
def sigma0_64:
  (_r64_1) as $r1 | (_r64_8) as $r8 | (_s64_7) as $s7 |
  bxor64($r1; $r8) as $x |
  bxor64($x; $s7);

def sigma1_64:
  (_r64_19) as $r19 | (_r64_61) as $r61 | (_s64_6) as $s6 |
  bxor64($r19; $r61) as $x |
  bxor64($x; $s6);

# ── Message schedule ──────────────────────────────────────────────────────────

# Callers always have the block as a derived value, never as their natural .
# so this takes it as a $arg rather than via pipe.
def make_schedule512($block):
  # W[0..15]: pack 8 bytes big-endian into each [hi, lo] 64-bit word
  [ range(16) as $i |
    [ ($block[$i*8  ] * 16777216) + ($block[$i*8+1] * 65536) + ($block[$i*8+2] * 256) + $block[$i*8+3],
      ($block[$i*8+4] * 16777216) + ($block[$i*8+5] * 65536) + ($block[$i*8+6] * 256) + $block[$i*8+7] ] ] |
  # W[16..79]: extend via σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
  # Unlike SHA-256, we cannot defer the mask: four 64-bit values summing directly
  # could exceed 2^66 > 2^53.  add64 carries correctly via [hi, lo] at each step.
  reduce range(16; 80) as $i (
    .;
    . as $w |
    . + [ add64(add64(add64(($w[$i-2]|sigma1_64); $w[$i-7]); ($w[$i-15]|sigma0_64)); $w[$i-16]) ]
  );

# ── Compression function ──────────────────────────────────────────────────────

# Input (.): [a,b,c,d,e,f,g,h] working variables (each a [hi,lo] pair)
# Args: ws — 80-word schedule, ks — 80 round constants (both as [hi,lo] pairs)
# Output: [a,b,c,d,e,f,g,h] after 80 rounds
def compress512($ws; $ks):
  reduce range(80) as $i (
    .;
    . as [$a, $b, $c, $d, $e, $f, $g, $h] |
    # T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
    add64(add64(add64(add64($h; ($e|Sigma1_64)); Ch64($e; $f; $g)); $ws[$i]); $ks[$i]) as $T1 |
    # T2 = Σ0(a) + Maj(a,b,c)
    add64(($a|Sigma0_64); Maj64($a; $b; $c)) as $T2 |
    # Rotate working variables
    [ add64($T1; $T2), $a, $b, $c, add64($d; $T1), $e, $f, $g ]
  );

def process_block512($block; $h; $k):
  make_schedule512($block) as $w |
  ($h | compress512($w; $k)) as $comp |
  [ range(8) as $i | add64($h[$i]; $comp[$i]) ];

# ── SHA-512 finalisation padding ──────────────────────────────────────────────

# Input (.): remaining (unprocessed) byte buffer after streaming
# Arg total_len: TOTAL original message length in bytes (for the length suffix)
#
# Appends: 0x80, zero bytes until total ≡ 112 (mod 128), 128-bit big-endian
# bit-count. Result is always 128 or 256 bytes (one or two final 128-byte blocks).
#
# The bit-count field is 128 bits (16 bytes).  For inputs < 2^61 bytes (all
# practical cases), the high 64 bits are always zero.
def sha512_final_pad($buf; $total_len):
  ($total_len * 8) as $bits |
  $buf + [128]
    + [ range(((111 - $total_len) % 128 + 128) % 128) | 0 ]
    + [ 0, 0, 0, 0, 0, 0, 0, 0,
        ($bits / 72057594037927936 | floor) % 256,
        ($bits / 281474976710656   | floor) % 256,
        ($bits / 1099511627776     | floor) % 256,
        ($bits / 4294967296        | floor) % 256,
        ($bits / 16777216          | floor) % 256,
        ($bits / 65536             | floor) % 256,
        ($bits / 256               | floor) % 256,
         $bits % 256 ];

# ── Streaming SHA-512 ─────────────────────────────────────────────────────────

# Arg gen: any generator that emits individual byte integers (0–255).
#
# SHA-512 compression happens *while* the generator runs — at most 127 buffered
# bytes exist at any moment, regardless of total input size.  After the generator
# is exhausted the remaining buffer is padded and the final 1–2 blocks processed.
def sha512_from_stream(gen):
  sha512_K as $k |
  # Streaming phase: one byte per reduce step, block processed when buf hits 128
  reduce gen as $byte (
    { h: sha512_H0, buf: [], len: 0 };
    .buf += [$byte] | .len += 1 |
    if (.buf | length) == 128 then
      process_block512(.buf; .h; $k) as $nh |
      .h = $nh | .buf = []
    else . end
  ) |
  # Finalisation phase: pad the remaining buffer and process 1–2 final blocks
  .h as $H |
  sha512_final_pad(.buf; .len) |
  . as $padded |
  (length / 128) as $nblocks |
  reduce range($nblocks) as $bi (
    $H;
    process_block512($padded[$bi * 128 : ($bi + 1) * 128]; .; $k)
  ) |
  map(word64_to_hex) | join("");

# ── Public convenience entry points ───────────────────────────────────────────

# Input (.): base64-encoded string (standard alphabet, "=" padding)
# Output: 128-character lowercase hex SHA-512 digest of the decoded bytes
def sha512_of_b64:
  sha512_from_stream(b64_stream_decode);

# Input (.): array of byte integers (0–255)
# Output: 128-character lowercase hex SHA-512 digest
def sha512_of_bytes:
  sha512_from_stream(.[]);
