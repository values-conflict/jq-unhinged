# b64.jq — Pure-jq base64 decoder and encoder (standard alphabet, "=" padding)
#
# Public entry points:
#
#   b64_stream_decode             — input (.): base64 string → generator of byte integers
#   b64_stream_encode(gen)        — gen: generator of byte integers → base64 string
#   b64_stream_encode(gen; wrap)  — same, wrapped at `wrap` chars per line (0 = no wrap)
#
# Bytes are represented as plain integers (0–255), not jq strings, so arbitrary
# binary data (bytes > 127) is handled correctly with no UTF-8 mangling.
#
# ── Performance characteristics (jq 1.7, measured on WSL2) ──────────────────
#
#   Bottleneck: 4× b64val (if/elif chain) per 4-character group, plus one
#   range step per group.  Timing scales linearly:
#
#     Input (binary)   Base64 chars    Wall time    Groups
#     ──────────────   ────────────    ─────────    ──────
#         1 KiB            1 368          ~5 ms       342
#        10 KiB           13 656         ~22 ms     3 414
#        50 KiB           68 268         ~99 ms    17 067
#
#   Rule of thumb: ~2 ms per KiB of binary input.
#
#   In pipelines that also call sha256.jq (~150 ms per KiB), b64 decode
#   contributes ≈ 1–2% of total wall time and is never the bottleneck.

# ── Base64 character → 6-bit value ────────────────────────────────────────
#
# RFC 4648 §4 Table 1 "The Base 64 Alphabet":
#
#   Value  Char    Value  Char    Value  Char    Value  Char
#       0  A          17  R          34  i          51  z
#       1  B          18  S          35  j          52  0
#       2  C          19  T          36  k          53  1
#       3  D          20  U          37  l          54  2
#       4  E          21  V          38  m          55  3
#       5  F          22  W          39  n          56  4
#       6  G          23  X          40  o          57  5
#       7  H          24  Y          41  p          58  6
#       8  I          25  Z          42  q          59  7
#       9  J          26  a          43  r          60  8
#      10  K          27  b          44  s          61  9
#      11  L          28  c          45  t          62  +
#      12  M          29  d          46  u          63  /
#      13  N          30  e          47  v    (pad)     =
#      14  O          31  f          48  w
#      15  P          32  g          49  x
#      16  Q          33  h          50  y
#
# Map a single base64 codepoint to its 6-bit value.
# Returns -1 for '=' (padding) or any invalid character.
def _b64val:
	if . >= 65 and . <= 90 then . - 65    # A–Z → 0–25
	elif . >= 97 and . <= 122 then . - 71 # a–z → 26–51  ('a'=97, 97−71=26)
	elif . >= 48 and . <= 57 then . + 4   # 0–9 → 52–61  ('0'=48, 48+4=52)
	elif . == 43 then 62                  # +   → 62
	elif . == 47 then 63                  # /   → 63
	else -1                               # = (padding) or invalid
	end
;

# ── Streaming decoder ──────────────────────────────────────────────────────
#
# RFC 4648 §4: "The encoding process represents 24-bit groups of input bits as
# output strings of 4 encoded characters.  Proceeding from left to right, a
# 24-bit input group is formed by concatenating 3 8-bit input groups.  These 24
# bits are then treated as 4 concatenated 6-bit groups, each of which is
# translated into a single character in the base 64 alphabet."
#
# RFC 4648 §4 padding (inverting the encoding rules for decoding):
#   (1) Final input quantum is a multiple of 24 bits → XXXX, no padding, 3 bytes out
#   (2) Final input quantum is exactly 8 bits        → XX==, 1 byte out
#   (3) Final input quantum is exactly 16 bits       → XXX=, 2 bytes out
#
# Input (.): base64-encoded string
# Output: generator — emits individual decoded byte integers (0–255).
#         Processes 4 input characters → 1, 2, or 3 output bytes:
#           "XX==" → 1 byte  (12 data bits)
#           "XXX=" → 2 bytes (18 data bits)
#           "XXXX" → 3 bytes (24 data bits)
def b64_stream_decode:
	explode as $chars
	| range(0; ($chars | length); 4) as $i
	| ($chars[$i:$i + 4] | map(_b64val)) as $v
	| if $v[2] == -1 then
		$v[0] * 4 + ($v[1] / 16 | floor)
	elif $v[3] == -1 then
		($v[0] * 4 + ($v[1] / 16 | floor)),
		(($v[1] % 16) * 16 + ($v[2] / 4 | floor))
	else
		($v[0] * 4 + ($v[1] / 16 | floor)),
		(($v[1] % 16) * 16 + ($v[2] / 4 | floor)),
		(($v[2] % 4) * 64 + $v[3])
	end
;

# ── Base64 value → character codepoint ────────────────────────────────────
#
# inverse of b64val: maps a 6-bit value (0–63) to its ASCII codepoint
#
# map a 6-bit value (0–63) to its base64 character codepoint (inverse of b64val)
def _b64_codepoint:
	if . < 26 then . + 65   # 0–25  → A–Z  ('A'=65)
	elif . < 52 then . + 71 # 26–51 → a–z  ('a'=97, 97−26=71)
	elif . < 62 then . - 4  # 52–61 → 0–9  ('0'=48, 48−52=−4)
	elif . == 62 then 43    # 62    → '+'
	else 47                 # 63    → '/'
	end
;

# ── Streaming encoder ──────────────────────────────────────────────────────
#
# RFC 4648 §4: 3 input bytes → 4 base64 characters, with '=' padding when
# the input length is not a multiple of 3:
#   n ≡ 1 (mod 3) → "XX=="  (1 data byte  → 2 base64 chars + "==")
#   n ≡ 2 (mod 3) → "XXX="  (2 data bytes → 3 base64 chars + "=")
#
# stream bytes in triples; emit one 4-char base64 group per triple;
# null sentinel triggers padding for any remaining 1–2 bytes
def _b64_groups(gen):
	foreach (gen, null) as $byte ({ b0: null, b1: null, group: null };
		.group = null
		| if $byte == null then
			if .b1 != null then
				.b0 as $b0
				| .b1 as $b1
				| .group = (
					[
						($b0 / 4 | floor | _b64_codepoint),
						(($b0 % 4) * 16 + ($b1 / 16 | floor) | _b64_codepoint),
						(($b1 % 16) * 4 | _b64_codepoint),
						61, # '='
						empty
					]
					| implode
				)
				| .b0 = null
				| .b1 = null
			elif .b0 != null then
				.b0 as $b0
				| .group = (
					[
						($b0 / 4 | floor | _b64_codepoint),
						(($b0 % 4) * 16 | _b64_codepoint),
						61, 61, # '=='
						empty
					]
					| implode
				)
				| .b0 = null
			else . end
		elif .b0 == null then
			.b0 = $byte
		elif .b1 == null then
			.b1 = $byte
		else
			.b0 as $b0
			| .b1 as $b1
			| .group = (
				[
					($b0 / 4 | floor | _b64_codepoint),
					(($b0 % 4) * 16 + ($b1 / 16 | floor) | _b64_codepoint),
					(($b1 % 16) * 4 + ($byte / 64 | floor) | _b64_codepoint),
					($byte % 64 | _b64_codepoint),
					empty
				]
				| implode
			)
			| .b0 = null
			| .b1 = null
		end
	; if .group != null then .group else empty end)
;

# gen: generator of byte integers (0–255)
# wrap: characters per output string (any positive integer, like base64 -w);
#       use 0 for no line-wrapping (emit a single string)
# output: generator of base64 strings
#   wrap=0 → exactly one string ("" for empty input)
#   wrap=N → one string per N-character line (empty input → no output)
def b64_stream_encode(gen; $wrap):
	foreach (_b64_groups(gen), null) as $group ({ line: "", readyLines: [] };
		if $group == null then
			if (.line | length) > 0 or $wrap == 0 then
				{ line: "", readyLines: [ .line ] }
			else { line: "", readyLines: [] } end
		else
			(.line + $group) as $newLine
			| ($newLine | length) as $len
			| (if $wrap == 0 then 0 else $len / $wrap | floor end) as $numLines
			| {
				line: $newLine[$numLines * $wrap:],
				readyLines: [
					range($numLines) as $i
					| $newLine[$i * $wrap:($i + 1) * $wrap],
						empty
				],
			}
		end
	; .readyLines[])
;

def b64_stream_encode(gen):
	b64_stream_encode(gen; 0)
;
