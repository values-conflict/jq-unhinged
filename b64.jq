# b64.jq — Pure-jq base64 decoder (standard alphabet, "=" padding)
#
# Public entry points:
#
#   b64_stream_decode  — input (.): base64 string → generator of byte integers
#   b64_decode         — input (.): base64 string → array of byte integers
#
# Bytes are represented as plain integers (0–255), not jq strings, so arbitrary
# binary data (bytes > 127) is handled correctly with no UTF-8 mangling.

# ── Base64 character → 6-bit value ────────────────────────────────────────

# Map a single base64 codepoint to its 6-bit value.
# Returns -1 for '=' (padding) or any invalid character.
def b64val:
  if   . >= 65 and . <= 90  then . - 65   # A–Z → 0–25
  elif . >= 97 and . <= 122 then . - 71   # a–z → 26–51  ('a'=97, 97−71=26)
  elif . >= 48 and . <= 57  then . + 4    # 0–9 → 52–61  ('0'=48, 48+4=52)
  elif . == 43               then 62       # + → 62
  elif . == 47               then 63       # / → 63
  else                            -1       # = (padding) or invalid
  end;

# ── Streaming decoder ──────────────────────────────────────────────────────

# Input (.): base64-encoded string
# Output: generator — emits individual decoded byte integers (0–255).
#         Processes 4 input characters → 1, 2, or 3 output bytes:
#           "XX==" → 1 byte  (12 data bits)
#           "XXX=" → 2 bytes (18 data bits)
#           "XXXX" → 3 bytes (24 data bits)
def b64_stream_decode:
  explode as $chars |
  range(0; ($chars | length); 4) as $i |
  ($chars[$i : $i + 4] | map(b64val)) as $v |
  if $v[2] == -1 then
    ($v[0] * 4 + ($v[1] / 16 | floor))
  elif $v[3] == -1 then
    ($v[0] * 4 + ($v[1] / 16 | floor)),
    (($v[1] % 16) * 16 + ($v[2] / 4 | floor))
  else
    ($v[0] * 4 + ($v[1] / 16 | floor)),
    (($v[1] % 16) * 16 + ($v[2] / 4 | floor)),
    (($v[2] % 4) * 64 + $v[3])
  end;

# ── Collecting decoder ─────────────────────────────────────────────────────

# Input (.): base64-encoded string
# Output: array of decoded byte integers (0–255)
def b64_decode: [ b64_stream_decode ];
