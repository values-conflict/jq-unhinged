# b64_tests.jq — test corpus for b64.jq

# b64val: A → 0,  Z → 25
include "b64"; b64val
65
0

include "b64"; b64val
90
25

# b64val: a → 26,  z → 51
include "b64"; b64val
97
26

include "b64"; b64val
122
51

# b64val: 0 → 52,  9 → 61
include "b64"; b64val
48
52

include "b64"; b64val
57
61

# b64val: + → 62,  / → 63
include "b64"; b64val
43
62

include "b64"; b64val
47
63

# b64val: = → -1 (padding sentinel)
include "b64"; b64val
61
-1

# b64_decode: empty string → empty array
include "b64"; b64_decode
""
[]

# b64_decode: "AA==" → one null byte
include "b64"; b64_decode
"AA=="
[0]

# b64_decode: "AQ==" → 0x01
include "b64"; b64_decode
"AQ=="
[1]

# b64_decode: "/w==" → 0xFF (high byte — no UTF-8 mangling)
include "b64"; b64_decode
"/w=="
[255]

# b64_decode: "AAA=" → two bytes [0, 0]
include "b64"; b64_decode
"AAA="
[0,0]

# b64_decode: "AAEC" → three bytes [0, 1, 2] (no padding)
include "b64"; b64_decode
"AAEC"
[0,1,2]

# b64_decode: high bytes across a group boundary — 0xFF 0xFE 0xFD
include "b64"; b64_decode
"//79"
[255,254,253]

# b64_decode: one full group + one padded → 4 bytes
include "b64"; b64_decode
"AAAAAA=="
[0,0,0,0]

# b64_decode: two full groups → 6 bytes
include "b64"; b64_decode
"AAAAAAAA"
[0,0,0,0,0,0]

# b64_stream_decode: same bytes as b64_decode for a 3-byte input
include "b64"; [b64_stream_decode]
"AAEC"
[0,1,2]

# ── Multi-group real-world inputs ─────────────────────────────────────────

# Docker image config (compact JSON) — 451 bytes, 7 streaming blocks + 1 final
include "b64"; b64_decode | length
"eyJjb25maWciOnsiRW52IjpbIlBBVEg9L3Vzci9sb2NhbC9zYmluOi91c3IvbG9jYWwvYmluOi91c3Ivc2JpbjovdXNyL2Jpbjovc2JpbjovYmluIl0sIkVudHJ5cG9pbnQiOltdLCJDbWQiOlsiYmFzaCJdfSwiY3JlYXRlZCI6IjIwMjYtMDQtMDZUMDA6MDA6MDBaIiwiaGlzdG9yeSI6W3siY3JlYXRlZCI6IjIwMjYtMDQtMDZUMDA6MDA6MDBaIiwiY3JlYXRlZF9ieSI6IiMgZGViaWFuLnNoIC0tYXJjaCAnYW1kNjQnIG91dC8gJ3RyaXhpZScgJ0AxNzc1NDMzNjAwJyIsImNvbW1lbnQiOiJkZWJ1ZXJyZW90eXBlIDAuMTcifV0sInJvb3RmcyI6eyJ0eXBlIjoibGF5ZXJzIiwiZGlmZl9pZHMiOlsic2hhMjU2OjQ3ZTY3M2UzMjgxN2ZiYWY1MzYxOTM2NDU4N2ViZjZiMmQ0MWYzZmQ1ZTAyYjNmYTZhM2IyZmQwMWI0N2RkZmIiXX0sIm9zIjoibGludXgiLCJhcmNoaXRlY3R1cmUiOiJhbWQ2NCJ9Cg=="
451

include "b64"; b64_decode | .[0]
"eyJjb25maWciOnsiRW52IjpbIlBBVEg9L3Vzci9sb2NhbC9zYmluOi91c3IvbG9jYWwvYmluOi91c3Ivc2JpbjovdXNyL2Jpbjovc2JpbjovYmluIl0sIkVudHJ5cG9pbnQiOltdLCJDbWQiOlsiYmFzaCJdfSwiY3JlYXRlZCI6IjIwMjYtMDQtMDZUMDA6MDA6MDBaIiwiaGlzdG9yeSI6W3siY3JlYXRlZCI6IjIwMjYtMDQtMDZUMDA6MDA6MDBaIiwiY3JlYXRlZF9ieSI6IiMgZGViaWFuLnNoIC0tYXJjaCAnYW1kNjQnIG91dC8gJ3RyaXhpZScgJ0AxNzc1NDMzNjAwJyIsImNvbW1lbnQiOiJkZWJ1ZXJyZW90eXBlIDAuMTcifV0sInJvb3RmcyI6eyJ0eXBlIjoibGF5ZXJzIiwiZGlmZl9pZHMiOlsic2hhMjU2OjQ3ZTY3M2UzMjgxN2ZiYWY1MzYxOTM2NDU4N2ViZjZiMmQ0MWYzZmQ1ZTAyYjNmYTZhM2IyZmQwMWI0N2RkZmIiXX0sIm9zIjoibGludXgiLCJhcmNoaXRlY3R1cmUiOiJhbWQ2NCJ9Cg=="
123

# Docker image config (pretty-printed JSON) — 396 bytes, 6 streaming blocks + 1 final
include "b64"; b64_decode | length
"ewoJImFyY2hpdGVjdHVyZSI6ICJhbWQ2NCIsCgkiY29uZmlnIjogewoJCSJDbWQiOiBbCgkJCSIvdHJ1ZSIKCQldCgl9LAoJImNyZWF0ZWQiOiAiMjAyMy0wMi0wMVQwNjo1MToxMVoiLAoJImhpc3RvcnkiOiBbCgkJewoJCQkiY3JlYXRlZCI6ICIyMDIzLTAyLTAxVDA2OjUxOjExWiIsCgkJCSJjcmVhdGVkX2J5IjogImh0dHBzOi8vZ2l0aHViLmNvbS90aWFub24vZG9ja2VyZmlsZXMvdHJlZS9tYXN0ZXIvdHJ1ZSIKCQl9CgldLAoJIm9zIjogImxpbnV4IiwKCSJyb290ZnMiOiB7CgkJImRpZmZfaWRzIjogWwoJCQkic2hhMjU2OjY1YjVhNDU5M2NjNjFkM2VhNmQzNTVmYjk3YzA0MzBkODIwZWUyMWFhODUzNWY1ZGU0NWU3NWMzMTk1NGI3NDMiCgkJXSwKCQkidHlwZSI6ICJsYXllcnMiCgl9Cn0K"
396

include "b64"; b64_decode | .[0:3]
"ewoJImFyY2hpdGVjdHVyZSI6ICJhbWQ2NCIsCgkiY29uZmlnIjogewoJCSJDbWQiOiBbCgkJCSIvdHJ1ZSIKCQldCgl9LAoJImNyZWF0ZWQiOiAiMjAyMy0wMi0wMVQwNjo1MToxMVoiLAoJImhpc3RvcnkiOiBbCgkJewoJCQkiY3JlYXRlZCI6ICIyMDIzLTAyLTAxVDA2OjUxOjExWiIsCgkJCSJjcmVhdGVkX2J5IjogImh0dHBzOi8vZ2l0aHViLmNvbS90aWFub24vZG9ja2VyZmlsZXMvdHJlZS9tYXN0ZXIvdHJ1ZSIKCQl9CgldLAoJIm9zIjogImxpbnV4IiwKCSJyb290ZnMiOiB7CgkJImRpZmZfaWRzIjogWwoJCQkic2hhMjU2OjY1YjVhNDU5M2NjNjFkM2VhNmQzNTVmYjk3YzA0MzBkODIwZWUyMWFhODUzNWY1ZGU0NWU3NWMzMTk1NGI3NDMiCgkJXSwKCQkidHlwZSI6ICJsYXllcnMiCgl9Cn0K"
[123,10,9]

# Gzip binary data — 117 bytes, 1 streaming block + 1 final; bytes > 127 test UTF-8 safety
# First two bytes are the gzip magic number: 0x1f=31, 0x8b=139 (both high bytes)
include "b64"; b64_decode | .[0:2]
"H4sIAAAAAAACAyspKk1loDEwAAJTU1MwDQTotIGhuQmcDRE3MzM0YlAwYKADKC0uSSxSUGAYoaDe1ceNiZERzmdisGMA8SoYHMB8Byx6HBgsGGA6QDQrmiwyXQPl1cDlIUG9wYaflWEUDDgAAIAGdJIABAAA"
[31,139]

include "b64"; b64_decode | length
"H4sIAAAAAAACAyspKk1loDEwAAJTU1MwDQTotIGhuQmcDRE3MzM0YlAwYKADKC0uSSxSUGAYoaDe1ceNiZERzmdisGMA8SoYHMB8Byx6HBgsGGA6QDQrmiwyXQPl1cDlIUG9wYaflWEUDDgAAIAGdJIABAAA"
117
