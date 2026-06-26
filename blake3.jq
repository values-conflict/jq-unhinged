# blake3.jq — Pure-jq BLAKE3 implementation (no bitwise builtins required)
#
# BLAKE3 specification: https://github.com/BLAKE3-team/BLAKE3-specs/blake3.pdf
#
# Public entry points:
#
#   blake3_from_stream(gen)   — gen: byte-integer generator → 64-char hex (256-bit)
#   blake3_from_stream(gen;n) — gen: byte-integer generator → 2*n-char hex (XOF)
#
# Bitwise primitives come from bits.jq, imported transitively through sha256.jq (see _blake3_IV below).
#
# ── Algorithm overview ────────────────────────────────────────────────────────
#
# BLAKE3 is a Merkle-tree hash.  Input is split into 1024-byte chunks; each
# chunk is compressed through up to 16 sequential 64-byte blocks.  Chunk
# chaining values (CVs) are merged pairwise up a binary tree; the root node
# produces output of arbitrary length (XOF) by re-running its final compression
# with an incrementing counter.
#
# The compression function G is derived from BLAKE2s, itself derived from
# ChaCha20.  It uses only 32-bit add/XOR/ROTR — no 64-bit pairs, no extended
# message schedule — making it simpler and faster than SHA-256 or SHA-512:
#
#   Band calls per 64-byte block:
#     SHA-512: ~2 112  (64-bit [hi,lo] pairs, 80 rounds)
#     SHA-256:   ~832  (32-bit, 64 rounds + schedule extension)
#     BLAKE3:    ~240  (32-bit, 7 rounds × 8 G-calls × 4 XOR + 16 final XOR)
#
# ── Performance characteristics (jq 1.7, measured on WSL2) ───────────────────
#
#   The bottleneck is the same as sha256.jq: band() calls at ~8.8 µs each.
#   BLAKE3 uses ~240 band calls per 64-byte block (vs SHA-256's 832), so it
#   runs ~2.7× faster in practice (theory predicts 3.5×; per-block interpreter
#   overhead is algorithm-independent and dilutes the gain).
#
#     Input (binary)   Base64 chars    Wall time    Chunks   Blocks
#     ──────────────   ────────────    ─────────    ──────   ──────
#         1 KiB            1 368         ~49 ms        1       16
#        10 KiB           13 656        ~455 ms       10      160
#        50 KiB           68 268        ~2.35 s       50      800
#
#   Rule of thumb: ~49 ms per KiB of binary input (~2.7× faster than sha256.jq).
#
#   Practical thresholds for the intended use case (manifest / config validation):
#     < 200 ms  →  ≤ ~4 KiB  — "feels instant"
#     < 1 s     →  ≤ ~20 KiB — acceptable for scripts
#     < 3 s     →  ≤ ~60 KiB — borderline for automation
#     > 5 s     →  ≥ ~100 KiB — too slow for interactive use
#
#   Docker / OCI image configs: 400 B – 2 KiB →  ~20–100 ms  ✓
#   Manifest JSON files:        1 KiB – 5 KiB →  ~50–250 ms  ✓
#   Actual layer tarballs:      MiB scale      →  minutes     ✗ (use host b3sum)

include "sha256";       # _sha256_H0 is aliased as _blake3_IV below
import "bits" as bits;  # band, bxor — the hot-path bitwise primitives

# ── Initialization vector ─────────────────────────────────────────────────────
#
# BLAKE3 specification §2.1: "The initialization vector (IV) is the SHA-256
# initialization vector: the first 32 bits of the fractional parts of the
# square roots of the first eight prime numbers."
#
# These eight words are identical to _sha256_H0 (defined in sha256.jq, cited
# from FIPS 180-4 §5.3.3).  We alias rather than duplicate, making the
# relationship structurally visible.

def _blake3_IV: _sha256_H0;

# ── Message word permutation ──────────────────────────────────────────────────
#
# BLAKE3 specification §2.2: the permutation applied to the 16 message words
# between rounds.  Applied 6 times (rounds 2–7); round 1 uses the original
# order.  Derived from BLAKE2's sigma schedule, simplified to a single fixed
# permutation repeated rather than a rotating table.

def _blake3_MSG_PERM: [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

# ── Domain-separation flags ───────────────────────────────────────────────────
#
# BLAKE3 specification §2.5, Table 2.  Stored in state word v[15] before each
# compression call.  Flags occupy disjoint bits, so they combine with addition
# rather than bitwise OR (which in jq would be the pipe operator — a footgun
# that would silently produce wrong results).

def _BLAKE3_CHUNK_START: 1;   # first block of a chunk
def _BLAKE3_CHUNK_END:   2;   # last block of a chunk
def _BLAKE3_PARENT:      4;   # parent node (merges two child CVs)
def _BLAKE3_ROOT:        8;   # root node (enables variable-length XOF output)
# BLAKE3_KEYED_HASH=16, BLAKE3_DERIVE_KEY_CONTEXT=32, BLAKE3_DERIVE_KEY_MATERIAL=64
# are defined in the spec but not implemented here (plain hashing only).

# ── Rotation constants ────────────────────────────────────────────────────────
#
# BLAKE3 specification §2.2: G uses ROTR32 by 16, 12, 8, and 7.
# _r7 is already defined in sha256.jq (imported above); the remaining three
# are BLAKE3-specific.  Inlined constants avoid pow(2;n) calls, same technique
# as sha256.jq's specialised rotations.
#
# _r16 is symmetric (rotation by exactly half the word width): both the shift
# and the wrap term use the same multiplier 65536, making it a simple 16-bit
# half-word swap: high 16 bits become low, low 16 bits become high.

def _r8:  (. / 256   | floor) + (. % 256   * 16777216);
def _r12: (. / 4096  | floor) + (. % 4096  * 1048576);
def _r16: (. / 65536 | floor) + (. % 65536 * 65536);

# ── G mixing function ─────────────────────────────────────────────────────────
#
# BLAKE3 specification §2.2:
#
#   G(v, a, b, c, d, x, y):
#     v[a] ← (v[a] + v[b] + x) mod 2³²
#     v[d] ← (v[d] ⊕ v[a]) ≫≫ 16
#     v[c] ← (v[c] + v[d])     mod 2³²
#     v[b] ← (v[b] ⊕ v[c]) ≫≫ 12
#     v[a] ← (v[a] + v[b] + y) mod 2³²
#     v[d] ← (v[d] ⊕ v[a]) ≫≫  8
#     v[c] ← (v[c] + v[d])     mod 2³²
#     v[b] ← (v[b] ⊕ v[c]) ≫≫  7
#
# Input (.): the 16-word state array v[0..15]; a, b, c, d are indices.
# jq array update (.[i] = v) is functional and produces a new array each call.
# XOR via the arithmetic identity bits::bxor(a;b) = a+b−2·band(a;b) from bits.jq:
# 1 band call per XOR → 4 band calls per G → 32 per round → 224 per compression.

def _blake3_G($a; $b; $c; $d; $x; $y):
  ((.[$a] + .[$b] + $x) % 4294967296) as $va  |
  (bits::bxor(.[$d]; $va) | _r16)     as $vd  |
  ((.[$c] + $vd) % 4294967296)        as $vc  |
  (bits::bxor(.[$b]; $vc) | _r12)     as $vb  |
  (($va + $vb + $y) % 4294967296)     as $va2 |
  (bits::bxor($vd; $va2) | _r8)       as $vd2 |
  (($vc + $vd2) % 4294967296)         as $vc2 |
  (bits::bxor($vb; $vc2) | _r7)       as $vb2 |
  .[$a] = $va2 | .[$b] = $vb2 | .[$c] = $vc2 | .[$d] = $vd2;

# ── Round function ────────────────────────────────────────────────────────────
#
# BLAKE3 specification §2.2: one round = column step + diagonal step, each
# consisting of four G calls.  The message words m[0..15] are the permuted
# schedule for this round.
#
# Column step  (mixes columns of the 4×4 state matrix):
#   G(v, 0, 4,  8, 12, m[ 0], m[ 1])
#   G(v, 1, 5,  9, 13, m[ 2], m[ 3])
#   G(v, 2, 6, 10, 14, m[ 4], m[ 5])
#   G(v, 3, 7, 11, 15, m[ 6], m[ 7])
# Diagonal step (mixes diagonals):
#   G(v, 0, 5, 10, 15, m[ 8], m[ 9])
#   G(v, 1, 6, 11, 12, m[10], m[11])
#   G(v, 2, 7,  8, 13, m[12], m[13])
#   G(v, 3, 4,  9, 14, m[14], m[15])

def _blake3_round($m):
  _blake3_G(0; 4;  8; 12; $m[0];  $m[1])  |
  _blake3_G(1; 5;  9; 13; $m[2];  $m[3])  |
  _blake3_G(2; 6; 10; 14; $m[4];  $m[5])  |
  _blake3_G(3; 7; 11; 15; $m[6];  $m[7])  |
  _blake3_G(0; 5; 10; 15; $m[8];  $m[9])  |
  _blake3_G(1; 6; 11; 12; $m[10]; $m[11]) |
  _blake3_G(2; 7;  8; 13; $m[12]; $m[13]) |
  _blake3_G(3; 4;  9; 14; $m[14]; $m[15]);

# Apply the message permutation to one 16-word schedule.
def _blake3_permute: _blake3_MSG_PERM as $p | [range(16) as $i | .[$p[$i]]];

# ── Compression function ──────────────────────────────────────────────────────
#
# BLAKE3 specification §2.3:
#
#   compress(cv, block_words, counter, block_len, flags):
#     v ← [cv[0..7], IV[0..3], counter_lo, counter_hi, block_len, flags]
#     for each of 7 rounds: round(v, schedule); permute(schedule)
#     for i in 0..7:
#       v[i]   ^= v[i+8]    (new chaining value in v[0..7])
#       v[i+8] ^= cv[i]     (finalization feedback into v[8..15])
#     return v   (all 16 words)
#
# The 16-word output is used two ways:
#   Non-root:  v[0..7] is the output chaining value (CV).
#   Root/XOF:  all 16 words are converted to little-endian bytes and
#              concatenated; counter increments for each additional 64-byte
#              output block.
#
# Precomputing all 7 permuted schedules before the round loop avoids
# re-deriving them inside reduce — the same approach as sha256.jq's
# make_schedule, but simpler: permutation rather than arithmetic extension.

def _blake3_compress($cv; $blk; $clo; $chi; $bl; $fl):
  _blake3_IV as $iv |
  (reduce range(6) as $_ ([$blk]; . + [.[length-1] | _blake3_permute])) as $sc |
  ($cv + [$iv[0], $iv[1], $iv[2], $iv[3], $clo, $chi, $bl, $fl]) as $s0 |
  reduce range(7) as $r ($s0; _blake3_round($sc[$r])) |
  . as $s |
  [ range(8) as $i | bits::bxor($s[$i]; $s[$i+8]) ] +
  [ range(8) as $i | bits::bxor($s[$i+8]; $cv[$i]) ];

# ── Little-endian helpers ─────────────────────────────────────────────────────
#
# BLAKE3 specification §2.1: "All integers are little-endian."
# Unlike SHA-256 and SHA-512 (big-endian), BLAKE3 packs and unpacks message
# words with the least-significant byte first.

def _blake3_pack_le($bytes):
  [ range(16) as $i |
    $bytes[$i*4]               +
    $bytes[$i*4 + 1] * 256     +
    $bytes[$i*4 + 2] * 65536   +
    $bytes[$i*4 + 3] * 16777216 ];

# 32-bit word → 4 bytes, least-significant byte first.
def _blake3_word_to_le_bytes:
  [ . % 256,
    (. / 256     | floor) % 256,
    (. / 65536   | floor) % 256,
    (. / 16777216 | floor) % 256 ];

# ── Output struct ─────────────────────────────────────────────────────────────
#
# BLAKE3 specification §2.4: "The Output struct captures the inputs to the
# final compression so that root output can be generated with varying counters."
#
# Fields:
#   icv  — input chaining value (8 words fed into the final compression)
#   blk  — 16-word message block for the final compression
#   bl   — block_len in bytes (0–64; actual data, padding not counted)
#   fl   — flags for the final compression (without _BLAKE3_ROOT)
#   ci   — chunk counter used when this output is for a chunk node;
#           always 0 for parent nodes (spec §2.4: "counter = 0 for parent nodes")
#
# chaining_value():  _blake3_compress(icv, blk, ci_lo, ci_hi, bl, fl)[0:8]
# root_output(n):    concat _blake3_compress(icv, blk, t, 0, bl, fl|ROOT)
#                    for t = 0, 1, 2, …, ceil(n/64)−1, truncated to n bytes

def _blake3_output_cv($o):
  _blake3_compress($o.icv; $o.blk; $o.ci % 4294967296; ($o.ci / 4294967296 | floor);
                  $o.bl; $o.fl) |
  .[0:8];

# ── Chunk processing ──────────────────────────────────────────────────────────
#
# BLAKE3 specification §2.4: "A chunk is a sequence of up to 1024 bytes,
# processed as up to 16 sequential 64-byte blocks.  The first block of a chunk
# carries the CHUNK_START flag; the last carries CHUNK_END.  A single-block
# chunk carries both.  All blocks within a chunk share the same counter value
# (the chunk's position in the input, counting from zero)."
#
# Returns an output struct for the chunk.  The last block's inputs (icv, blk,
# bl, fl, ci) are preserved so the root can re-compress with _BLAKE3_ROOT and
# a varying output counter without reprocessing the whole chunk.

def _blake3_chunk_output($bytes; $ci):
  ($bytes | length) as $total |
  (([$total, 1] | max) + 63) / 64 | floor as $nblk |
  (if $nblk == 1 then _BLAKE3_CHUNK_START else 0 end) as $only |
  ($ci % 4294967296)              as $clo |
  ($ci / 4294967296 | floor)      as $chi |
  # Process all blocks before the last, threading the chaining value.
  # Block 0 carries CHUNK_START; middle blocks carry no flags.
  (reduce range($nblk - 1) as $bi (
    _blake3_IV;
    ($bi * 64) as $s |
    (. as $cv |
     _blake3_compress($cv; _blake3_pack_le($bytes[$s : $s + 64]);
                     $clo; $chi; 64;
                     if $bi == 0 then _BLAKE3_CHUNK_START else 0 end) |
     .[0:8])
  )) as $icv |
  # Last block: may be shorter than 64 bytes; padded with zeros for packing
  # (block_len records the real byte count, so the spec's padding is harmless).
  (($nblk - 1) * 64) as $ls |
  ([$total - $ls, 64] | min) as $last_bl |
  ($bytes[$ls : $ls + $last_bl] + [range(64 - $last_bl) | 0]) as $last_pad |
  { icv: $icv,
    blk: _blake3_pack_le($last_pad),
    bl:  $last_bl,
    fl:  ($only + _BLAKE3_CHUNK_END),
    ci:  $ci };

# ── Parent node ───────────────────────────────────────────────────────────────
#
# BLAKE3 specification §2.4: "A parent node takes the chaining values of its
# two children as its 16-word message block (left CV as words 0–7, right CV as
# words 8–15).  counter = 0, block_len = 64, flags = PARENT."

def _blake3_parent_output($lcv; $rcv):
  { icv: _blake3_IV,
    blk: ($lcv + $rcv),
    bl:  64,
    fl:  _BLAKE3_PARENT,
    ci:  0 };

# ── Merkle tree reduction ─────────────────────────────────────────────────────
#
# BLAKE3 specification §2.4: the binary Merkle tree is built left-to-right.
# At each level, adjacent pairs of nodes are merged; an odd rightmost node
# passes to the next level unmerged.  The recursion terminates when only one
# root node remains.
#
# This implementation collects all chunk outputs first, then reduces bottom-up.
# Recursion depth ≤ ⌈log₂(chunks)⌉ ≤ 20 for inputs up to 1 GiB, so stack
# depth is trivially bounded.  The tail-recursive call is TCO-eligible in jq.

def _blake3_tree_reduce:
  if length == 1 then .[0]
  else
    [ range(0; length; 2) as $i |
      if $i + 1 < length
      then _blake3_parent_output(_blake3_output_cv(.[$i]);
                                _blake3_output_cv(.[$i + 1]))
      else .[$i]
      end ] |
    _blake3_tree_reduce
  end;

# ── Variable output (XOF) ─────────────────────────────────────────────────────
#
# BLAKE3 specification §2.5: "Root output is produced by successive calls to
# compress() with the ROOT flag added and an incrementing counter t = 0, 1, 2 …
# Each call produces 64 output bytes.  The concatenation is truncated to the
# requested output length."
#
# The counter here is an output-block counter, distinct from the chunk counter
# stored in $root.ci.  Root output always starts at t = 0 regardless of which
# chunk was the root.

def _blake3_root_hex($root; $nbytes):
  (($nbytes + 63) / 64 | floor) as $nblocks |
  ("0123456789abcdef" | explode) as $hex |
  [ range($nblocks) as $t |
    _blake3_compress($root.icv; $root.blk; $t; 0; $root.bl; $root.fl + _BLAKE3_ROOT) |
    .[] | _blake3_word_to_le_bytes | .[]
  ] [:$nbytes] |
  [ .[] as $b | [$hex[$b / 16 | floor], $hex[$b % 16]] | implode ] |
  join("");

# ── Streaming BLAKE3 ──────────────────────────────────────────────────────────
#
# Arg gen:    any generator that emits individual byte integers (0–255).
# Arg nbytes: output length in bytes (default 32 = 256-bit digest).
#
# Bytes are chunked incrementally: the foreach state accumulates bytes into a
# 1024-byte buffer; each completed buffer is immediately hashed into a compact
# chunk output struct and the raw bytes are discarded.  The null sentinel flushes
# any remaining bytes and ensures at least one chunk for empty input.  Chunk
# outputs are collected in the state and merged up the Merkle tree at the end.

def blake3_from_stream(gen; $nbytes):
  foreach (gen, null) as $byte (
    {buf: [], ci: 0, chunks: []};
    if $byte != null then
      if (.buf | length) == 1023 then
        .ci as $ci |
        {buf: [], ci: ($ci + 1), chunks: (.chunks + [_blake3_chunk_output(.buf + [$byte]; $ci)])}
      else
        .buf += [$byte]
      end
    end;
    if $byte != null then
      empty
    elif (.buf | length) > 0 or (.chunks | length) == 0 then
      .chunks + [_blake3_chunk_output(.buf; .ci)]
    else
      .chunks
    end
  ) |
  _blake3_tree_reduce |
  _blake3_root_hex(.; $nbytes);

def blake3_from_stream(gen): blake3_from_stream(gen; 32);
