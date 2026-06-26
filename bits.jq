# bits.jq — shared bitwise primitives for sha256.jq and sha512.jq
#
# ── Hot-path warning ─────────────────────────────────────────────────────────
#
# Every function in this file is on the critical performance path.  SHA-256
# invokes band ~832 times per 64-byte block; SHA-512 invokes it ~2 112 times
# per 128-byte block.  At ~8.8 µs per band call (jq 1.7, WSL2), a single
# extra operation per call is measurable.  Profile carefully before altering
# anything here.
#
# ── Core identities ──────────────────────────────────────────────────────────
#
#   bxor(a,b) = a + b − 2·band(a,b)
#   bor(a,b)  = a + b −   band(a,b)
#
# Only band requires bit-level logic.  We implement it via a 256-entry nibble
# lookup table (indexed by a_nibble*16 + b_nibble), processing 4 bits at a
# time — 8 lookups cover all 32 bits with no inner loop.

# Nibble AND table: T[a*16+b] = a AND b  for a, b in 0..15
def _nat:
	[
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
		0, 0, 2, 2, 0, 0, 2, 2, 0, 0, 2, 2, 0, 0, 2, 2,
		0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3,
		0, 0, 0, 0, 4, 4, 4, 4, 0, 0, 0, 0, 4, 4, 4, 4,
		0, 1, 0, 1, 4, 5, 4, 5, 0, 1, 0, 1, 4, 5, 4, 5,
		0, 0, 2, 2, 4, 4, 6, 6, 0, 0, 2, 2, 4, 4, 6, 6,
		0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
		0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8, 8,
		0, 1, 0, 1, 0, 1, 0, 1, 8, 9, 8, 9, 8, 9, 8, 9,
		0, 0, 2, 2, 0, 0, 2, 2, 8, 8, 10, 10, 8, 8, 10, 10,
		0, 1, 2, 3, 0, 1, 2, 3, 8, 9, 10, 11, 8, 9, 10, 11,
		0, 0, 0, 0, 4, 4, 4, 4, 8, 8, 8, 8, 12, 12, 12, 12,
		0, 1, 0, 1, 4, 5, 4, 5, 8, 9, 8, 9, 12, 13, 12, 13,
		0, 0, 2, 2, 4, 4, 6, 6, 8, 8, 10, 10, 12, 12, 14, 14,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		empty
	]
;

# 32-bit AND: 8 nibble lookups, no loops
def band($a; $b):
	_nat as $t
	| $t[($a % 16) * 16 + ($b % 16)]
	+ $t[(($a / 16 | floor) % 16) * 16 + (($b / 16 | floor) % 16)]
	* 16
	+ $t[(($a / 256 | floor) % 16) * 16 + (($b / 256 | floor) % 16)]
	* 256
	+ $t[(($a / 4096 | floor) % 16) * 16 + (($b / 4096 | floor) % 16)]
	* 4096
	+ $t[(($a / 65536 | floor) % 16) * 16
	+ (($b / 65536 | floor) % 16)] * 65536
	+ $t[(($a / 1048576 | floor) % 16) * 16
	+ (($b / 1048576 | floor) % 16)] * 1048576
	+ $t[(($a / 16777216 | floor) % 16) * 16
	+ (($b / 16777216 | floor) % 16)] * 16777216
	+ $t[($a / 268435456 | floor) * 16 + ($b / 268435456 | floor)]
	* 268435456
;

# 32-bit XOR via arithmetic identity: a XOR b = a + b - 2*(a AND b)
def bxor($a; $b):
	band($a; $b) as $ab
	| $a + $b - 2 * $ab
;

# Convert a 32-bit word to an 8-character lowercase hex string.
# Called 8× per SHA-256 digest and 16× per SHA-512 digest — not on the inner loop.
def word_to_hex:
	("0123456789abcdef" | explode) as $hex
	| [
		268435456,
		16777216,
		1048576,
		65536,
		4096,
		256,
		16,
		1,
		empty
	] as $pows
	| [ range(8) as $i | $hex[(. / $pows[$i] | floor) % 16] ]
	| implode
;
