# tar.jq -- pure-jq POSIX ustar / GNU tar reader
#
# Public entry points:
#
#   tar_entries_from_stream(gen)
#     gen: generator of byte integers (0-255) -- yields one object per archive entry
#
#   tar_entries_from_stream(gen; collectData)
#     collectData: filter evaluated on each parsed header before data is read
#     when false, data bytes are skipped and the entry is emitted with data: []
#     useful for header-only listing in O(1) memory:
#       tar_entries_from_stream(gen; false)             -- all headers, no data
#       tar_entries_from_stream(gen; .name == "x.txt")  -- data only for x.txt
#
# Each emitted object has:
#   name       -- full path string (ustar prefix folded in; GNU long name applied)
#   mode       -- integer (eg 0o644 = 420)
#   uid, gid   -- integers
#   size       -- integer (byte count of file data)
#   mtime      -- integer (Unix seconds)
#   type       -- "0"=regular, "2"=symlink, "5"=directory, "1"=hard link, etc.
#                 old-format null typeflag is normalised to "0"
#   linkname   -- symlink / hard-link target
#   magic      -- "ustar" (POSIX), "ustar  " (GNU), or "" (old format)
#   version    -- "00" (POSIX) or "" (old format / GNU)
#   uname, gname  -- owner / group name strings
#   devmajor, devminor  -- integers
#   data       -- array of byte integers (0-255); [] when collectData is false or
#                 entry has no data (directories, symlinks, devices, etc.)
#
# GNU long-name entries (typeflag "L"/"K") are consumed internally; the long
# name is applied to the next real entry and never yielded on its own.
#
# Not supported:
#   pax extended headers (typeflag "x"/"g")
#   GNU sparse files (typeflag "S")
#   base-256 numeric encoding (files larger than ~8 GiB)
#
# Performance: O(n) time.  peak memory ≈ size of the largest single entry when
# collectData is true; O(1) memory per entry when collectData is false (only
# the 512-byte header block is ever buffered in that case).
#
# The EOF trailer (two 512-byte zero blocks at archive end) is optional -- a
# stream that ends mid-block or with no trailer at all is handled gracefully;
# foreach simply exhausts the generator and any partial trailing state is
# discarded.
#
# TODO: a streaming variant could emit the parsed header first, then individual
# data bytes (the way gzip_from_stream emits decompressed bytes), trading caller
# complexity for O(1) memory and enabling streaming transforms on arbitrarily
# large tar entries without ever buffering the full data
#
# Composes naturally with gzip_from_stream and b64_stream_decode:
#   include "b64"; include "gzip"; include "tar";
#   tar_entries_from_stream(gzip_from_stream(b64_stream_decode))

# ── field parsers ─────────────────────────────────────────────────────────────

# null/space-padded octal ASCII field (array of bytes) → integer
def _tar_octal:
	if .[0] >= 128 then
		error("tar: base-256 numeric field not supported (file too large for pure-jq)")
	else
		reduce (.[] | select(. >= 48 and . <= 55)) as $b (0; . * 8 + ($b - 48))
	end;

# null-terminated byte field → string
def _tar_str:
	[ .[] | select(. != 0) ] | implode;

# ustar prefix (if non-empty) prepended with "/" to form the full path
def _tar_fullname:
	if .prefix != "" then .prefix + "/" + .name else .name end;

# ── header parser ─────────────────────────────────────────────────────────────

# 512-byte array → header object
# includes a raw "prefix" field used internally; removed before emitting
def _tar_header:
	{
		name:     (.[0:100]   | _tar_str),
		mode:     (.[100:108] | _tar_octal),
		uid:      (.[108:116] | _tar_octal),
		gid:      (.[116:124] | _tar_octal),
		size:     (.[124:136] | _tar_octal),
		mtime:    (.[136:148] | _tar_octal),
		type:     (.[156:157] | _tar_str | if . == "" then "0" else . end),
		linkname: (.[157:257] | _tar_str),
		magic:    (.[257:263] | _tar_str),
		version:  (.[263:265] | _tar_str),
		uname:    (.[265:297] | _tar_str),
		gname:    (.[297:329] | _tar_str),
		devmajor: (.[329:337] | _tar_octal),
		devminor: (.[337:345] | _tar_octal),
		prefix:   (.[345:500] | _tar_str),
	};

# ── state machine ─────────────────────────────────────────────────────────────
#
# state fields:
#   p            current phase: "hdr" | "dat" | "skp" | "end"
#   buf          byte accumulation buffer (header block or file data)
#   ent          parsed header (set in "dat"; null otherwise)
#   rem          bytes remaining to skip ("skp" only)
#   longname     pending GNU long filename for next real entry (null or string)
#   longlinkname pending GNU long link name for next real entry (null or string)
#   emit         null, or the entry object to yield this step
#
# phase flow:
#   hdr ---(512 non-zero bytes)--→ dat ---(size bytes, pad>0)--→ skp --→ hdr
#    │                              └---(size bytes, pad=0)--------→ hdr
#    └---(512 zero bytes)--→ end
#
# "skp" doubles as a data-skip path: when collectData is false for a non-zero
# entry, rem is set to ⌈size/512⌉×512, skipping data+padding in one shot

def tar_entries_from_stream(gen; collectData):
	# build and emit an entry object; clears longname, longlinkname, ent
	def _emit($h; $data):
		(if .longname != null then .longname else ($h | _tar_fullname) end) as $name |
		(if .longlinkname != null then .longlinkname else $h.linkname end) as $lnk |
		.emit = (($h | del(.prefix)) + {name: $name, linkname: $lnk, data: $data}) |
		.longname = null |
		.longlinkname = null |
		.ent = null;

	def _tar_step($b):
		if .p == "end" then .emit = null

		elif .p == "hdr" then
			.emit = null |
			.buf += [$b] |
			if (.buf | length) < 512 then .
			else
				if (.buf | all(. == 0)) then .p = "end"
				else
					(.buf | _tar_header) as $h |
					.buf = [] |
					.ent = $h |
					if $h.size == 0 then
						if $h.type == "L" or $h.type == "K" then
							# zero-size GNU long-name stub (unusual); drop it
							.ent = null | .p = "hdr"
						else
							_emit($h; []) | .p = "hdr"
						end
					elif $h.type == "L" or $h.type == "K" then
						# always collect data for GNU long-name entries
						.p = "dat"
					elif ($h | collectData) then
						.p = "dat"
					else
						# skip data+padding without buffering; emit header now
						_emit($h; []) |
						((($h.size + 511) / 512 | floor) * 512) as $total |
						.p = "skp" | .rem = $total
					end
				end
			end

		elif .p == "dat" then
			.emit = null |
			.buf += [$b] |
			if (.buf | length) < .ent.size then .
			else
				(.ent.size % 512) as $modsize |
				(if $modsize == 0 then 0 else 512 - $modsize end) as $skip |
				if .ent.type == "L" then
					.longname = (.buf | _tar_str) |
					.ent = null | .buf = []
				elif .ent.type == "K" then
					.longlinkname = (.buf | _tar_str) |
					.ent = null | .buf = []
				else
					.ent as $ent |
					_emit($ent; .buf) |
					.buf = []
				end |
				if $skip == 0 then .p = "hdr"
				else .p = "skp" | .rem = $skip
				end
			end

		elif .p == "skp" then
			.emit = null |
			.rem -= 1 |
			if .rem == 0 then .p = "hdr" end

		else
			.emit = null
		end;

	foreach gen as $b (
		{
			p: "hdr",
			buf: [],
			ent: null,
			rem: 0,
			longname: null,
			longlinkname: null,
			emit: null,
		};
		_tar_step($b);
		if .emit != null then .emit else empty end
	);

def tar_entries_from_stream(gen):
	tar_entries_from_stream(gen; true);
