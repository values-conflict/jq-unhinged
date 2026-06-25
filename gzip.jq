# gzip.jq — Pure-jq gzip decompressor (RFC 1951 DEFLATE + RFC 1952 gzip wrapper)
#
# Public entry points:
#
#   gzip_from_stream(gen) — gen: generator of compressed byte integers
#                         → generator of decompressed byte integers
#
# The decompressor is a streaming state machine driven by jq's `foreach`.  It
# consumes one compressed byte per iteration and emits decompressed bytes
# immediately, keeping only the DEFLATE sliding window (≤ 32 768 bytes) in memory.
#
# ── Bit-buffer convention (RFC 1951 §3.1.1) ──────────────────────────────────
#
#   DEFLATE packs bits LSB-first within each byte: the first received bit sits at
#   position 0 (LSB) of .v.  .n counts the valid bits.  Reading k bits:
#     value  =  .v % p2[k]            (extract k LSBs)
#     .v     =  .v / p2[k] | floor    (shift right k positions)
#     .n    -=  k
#
# ── Huffman code convention (RFC 1951 §3.1.1) ─────────────────────────────────
#
#   Huffman codes are transmitted MSB-first.  After accumulating L bits the
#   canonical code value equals bit_reverse(.v % p2[L], L).
#   _gz_htable stores bit-reversed keys so decode is one direct array lookup.

# ── Bit utilities ─────────────────────────────────────────────────────────────

# Integer powers of two, indices 0–24 (covers all bit-buffer shifts in DEFLATE).
def _gz_p2: [
  1, 2, 4, 8, 16, 32, 64, 128,
  256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
  65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216
];

# Reverse the low $len bits of $val.
# Used to convert MSB-first canonical codes to LSB-first bit-buffer keys.
def _gz_rev($val; $len):
  _gz_p2 as $p2 |
  reduce range($len) as $i (
    0;
    . + (($val / $p2[$i] | floor) % 2) * $p2[$len - 1 - $i]
  );

# ── Huffman decode table ──────────────────────────────────────────────────────
#
# RFC 1951 §3.2.2: canonical codes are assigned in symbol order within each
# bit-length, starting from the shortest length.
#
# _gz_htable builds a 32 768-entry lookup array T where:
#   T[.v % 32768] = {sym: <symbol>, len: <code bit-count>}
# The index is the bit-reversed canonical code, zero-extended to 15 bits, which
# equals the low L bits of the bit buffer when an L-bit code is present.
#
# For a length-L symbol with reversed value $rev, all 15-bit patterns that share
# the same low L bits are filled: positions $rev, $rev+2^L, $rev+2·2^L, …

def _gz_htable($lengths):
  _gz_p2 as $p2 |

  # Count codes at each bit-length
  (reduce range($lengths | length) as $i (
    {};
    if $lengths[$i] > 0
    then ($lengths[$i] | tostring) as $k | .[$k] = (.[$k] // 0) + 1
    else .
    end
  )) as $cnt |

  # First canonical code per bit-length (RFC 1951 §3.2.2)
  reduce range(1; 16) as $L (
    {c: 0, fc: {}};
    .fc[$L | tostring] = .c |
    .c = (.c + ($cnt[$L | tostring] // 0)) * 2
  ) | .fc as $fc |

  # Assign codes, bit-reverse, fill 32 768-entry table
  reduce range($lengths | length) as $sym (
    {tbl: [range(32768) | null], nc: {}};
    ($lengths[$sym]) as $L |
    if $L == 0 then .
    else
      ($L | tostring) as $Ls |
      (.nc[$Ls] // ($fc[$Ls] // 0)) as $code |
      _gz_rev($code; $L) as $rev |
      reduce range($p2[15 - $L]) as $k (
        .;
        .tbl[$rev + $k * $p2[$L]] = {sym: $sym, len: $L}
      ) |
      .nc[$Ls] = $code + 1
    end
  ) | .tbl;

# ── DEFLATE length / distance tables (RFC 1951 §3.2.5, Tables 1–2) ───────────

# Index: litlen symbol − 257.  Value: [extra_bits, base_length].
def _gz_lbase: [
  [0,3],[0,4],[0,5],[0,6],[0,7],[0,8],[0,9],[0,10],
  [1,11],[1,13],[1,15],[1,17],
  [2,19],[2,23],[2,27],[2,31],
  [3,35],[3,43],[3,51],[3,59],
  [4,67],[4,83],[4,99],[4,115],
  [5,131],[5,163],[5,195],[5,227],
  [0,258]
];

# Index: distance symbol.  Value: [extra_bits, base_distance].
def _gz_dbase: [
  [0,1],[0,2],[0,3],[0,4],
  [1,5],[1,7],[2,9],[2,13],
  [3,17],[3,25],[4,33],[4,49],
  [5,65],[5,97],[6,129],[6,193],
  [7,257],[7,385],[8,513],[8,769],
  [9,1025],[9,1537],[10,2049],[10,3073],
  [11,4097],[11,6145],[12,8193],[12,12289],
  [13,16385],[13,24577]
];

# Permutation order for code-length alphabet entries (RFC 1951 §3.2.7)
def _gz_clord: [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];

# ── Fixed Huffman tables (RFC 1951 §3.2.6) ───────────────────────────────────
#
# Literal/length alphabet (288 symbols):
#   0–143   → 8-bit codes  00110000–10111111
#   144–255 → 9-bit codes 110010000–111111111
#   256–279 → 7-bit codes   0000000–0010111
#   280–287 → 8-bit codes  11000000–11000111
#
# Distance alphabet (30 symbols): all 5-bit codes.

def _gz_fixed_ll_tbl:
  _gz_htable([
    range(288) |
    if   . <= 143 then 8
    elif . <= 255 then 9
    elif . <= 279 then 7
    else               8
    end
  ]);

def _gz_fixed_d_tbl:
  _gz_htable([range(30) | 5]);

# ── Public entry points ───────────────────────────────────────────────────────

# Input: generator of compressed byte integers → generator of decompressed byte integers
def gzip_from_stream(gen):
  _gz_p2           as $p2     |
  _gz_lbase        as $lbase  |
  _gz_dbase        as $dbase  |
  _gz_clord        as $clord  |
  _gz_fixed_ll_tbl as $fll    |
  _gz_fixed_d_tbl  as $fdd    |

  # Emit byte $b: append to per-step flush buffer and sliding window; trim window.
  def _emit($b):
    .out += [$b] |
    .w   += [$b] |
    if (.w | length) > 40000 then .w = .w[-32768:] else . end;

  # ── State machine ─────────────────────────────────────────────────────────
  #
  # State fields:
  #   v     — bit buffer (LSB = first received bit)
  #   n     — valid bits in v
  #   w     — sliding window: last ≤ 32 768 decompressed bytes (LZ77 back-refs)
  #   ph    — current phase name
  #   out   — bytes decoded this step; emitted by foreach extract, cleared each update
  #   flg   — gzip FLG byte (RFC 1952 §2.3.1)
  #   hq    — queue of remaining optional-header phases
  #   rem   — multi-purpose counter (bytes to skip/copy, CL codes to read)
  #   bf    — BFINAL: 1 = last DEFLATE block
  #   sym   — scratch: most recently decoded Huffman symbol
  #   ll    — active lit/len (or CL-setup) Huffman table
  #   dd    — active distance Huffman table
  #   br    — extra-bit count for length codes
  #   bd    — back-reference distance (accumulated)
  #   br2   — extra-bit count for distance codes
  #   lbuf  — code-length accumulation buffer (dynamic Huffman setup)
  #   lnum  — total code lengths still to read
  #   lpos  — position in $clord while reading CL alphabet entries
  #   hlit  — HLIT+257 (lit/len code count, saved from dy0)
  #   hdist — HDIST+1 (distance code count, saved from dy0)
  #   prev  — last decoded code length (for CL repeat codes 16/17/18)

  def _gz_drain:
    # Advance to next pending optional header field, or to first DEFLATE block.
    def _next_hdr:
      if (.hq | length) == 0 then .ph = "db"
      else .ph = .hq[0] | .hq = .hq[1:]
      end;

    # Discard bits to reach the next byte boundary.
    def _align:
      (.n % 8) as $r |
      if $r == 0 then . else .v = (.v / $p2[$r] | floor) | .n -= $r end;

    # Decode one Huffman symbol; .sym = null if not enough bits available.
    def _decode($tbl):
      if .n < 1 then .sym = null
      else
        $tbl[.v % 32768] as $e |
        if   $e == null  then error("gzip: invalid Huffman code (ph=\(.ph))")
        elif .n < $e.len then .sym = null
        else .sym = $e.sym | .v = (.v / $p2[$e.len] | floor) | .n -= $e.len
        end
      end;

    def _step:
      .ph as $ph |

      ## ── GZIP HEADER (RFC 1952 §2.3) ───────────────────────────────────────

      if   $ph == "h0" then   # ID1 = 0x1f
        if .n < 8 then .
        else (.v % 256) as $b |
          if $b != 31  then error("gzip: bad ID1 (got \($b))")
          else .v = (.v/256|floor) | .n -= 8 | .ph = "h1" | _step end
        end

      elif $ph == "h1" then   # ID2 = 0x8b
        if .n < 8 then .
        else (.v % 256) as $b |
          if $b != 139 then error("gzip: bad ID2 (got \($b))")
          else .v = (.v/256|floor) | .n -= 8 | .ph = "h2" | _step end
        end

      elif $ph == "h2" then   # CM = 8 (deflate only)
        if .n < 8 then .
        else (.v % 256) as $b |
          if $b != 8 then error("gzip: unsupported CM \($b)")
          else .v = (.v/256|floor) | .n -= 8 | .ph = "h3" | _step end
        end

      elif $ph == "h3" then   # FLG
        if .n < 8 then .
        else .flg = (.v%256) | .v = (.v/256|floor) | .n -= 8 |
          .rem = 6 | .ph = "h4" | _step
        end

      elif $ph == "h4" then   # skip MTIME(4) + XFL(1) + OS(1)
        if .n < 8 then .
        else .v = (.v/256|floor) | .n -= 8 | .rem -= 1 |
          if .rem > 0 then _step
          else
            .hq = ([
              (if (.flg / 4  | floor) % 2 == 1 then "hx0" else empty end),
              (if (.flg / 8  | floor) % 2 == 1 then "hn"  else empty end),
              (if (.flg / 16 | floor) % 2 == 1 then "hc"  else empty end),
              (if (.flg / 2  | floor) % 2 == 1 then "hh0" else empty end)
            ]) |
            _next_hdr | _step
          end
        end

      elif $ph == "hx0" then  # FEXTRA: XLEN LSB
        if .n < 8 then .
        else .rem = (.v%256) | .v = (.v/256|floor) | .n -= 8 | .ph = "hx1" | _step end

      elif $ph == "hx1" then  # FEXTRA: XLEN MSB
        if .n < 8 then .
        else .rem += (.v%256)*256 | .v = (.v/256|floor) | .n -= 8 | .ph = "hx" | _step end

      elif $ph == "hx" then   # FEXTRA: skip rem bytes
        if   .rem == 0 then _next_hdr | _step
        elif .n   <  8 then .
        else .v = (.v/256|floor) | .n -= 8 | .rem -= 1 | _step
        end

      elif $ph == "hn" then   # FNAME: skip null-terminated filename
        if .n < 8 then .
        else (.v%256) as $b | .v = (.v/256|floor) | .n -= 8 |
          if $b == 0 then _next_hdr | _step else _step end
        end

      elif $ph == "hc" then   # FCOMMENT: skip null-terminated comment
        if .n < 8 then .
        else (.v%256) as $b | .v = (.v/256|floor) | .n -= 8 |
          if $b == 0 then _next_hdr | _step else _step end
        end

      elif $ph == "hh0" then  # FHCRC: skip 2-byte header CRC
        if .n < 8 then .
        else .v = (.v/256|floor) | .n -= 8 | .ph = "hh1" | _step end

      elif $ph == "hh1" then
        if .n < 8 then .
        else .v = (.v/256|floor) | .n -= 8 | _next_hdr | _step end

      ## ── DEFLATE BLOCK HEADER (RFC 1951 §3.2.3) ────────────────────────────

      elif $ph == "db" then   # BFINAL(1) + BTYPE(2) = 3 bits
        if .n < 3 then .
        else
          .bf = (.v % 2) |
          (.v/2|floor) as $v1 | ($v1 % 4) as $btype |
          .v = ($v1/4|floor) | .n -= 3 |
          if   $btype == 0 then .ph = "sa"  | _step
          elif $btype == 1 then .ll = $fll | .dd = $fdd | .ph = "fl" | _step
          elif $btype == 2 then .ph = "dy0" | _step
          else error("gzip: reserved DEFLATE block type")
          end
        end

      ## ── STORED BLOCK (BTYPE=00, RFC 1951 §3.2.4) ──────────────────────────

      elif $ph == "sa"  then _align | .ph = "sl0" | _step   # align to byte boundary

      elif $ph == "sl0" then  # LEN byte 0
        if .n < 8 then .
        else .rem = (.v%256) | .v = (.v/256|floor) | .n -= 8 | .ph = "sl1" | _step end

      elif $ph == "sl1" then  # LEN byte 1
        if .n < 8 then .
        else .rem += (.v%256)*256 | .v = (.v/256|floor) | .n -= 8 | .ph = "sn0" | _step end

      elif $ph == "sn0" then  # NLEN byte 0 (discard; validity check omitted)
        if .n < 8 then .
        else .v = (.v/256|floor) | .n -= 8 | .ph = "sn1" | _step end

      elif $ph == "sn1" then  # NLEN byte 1 (discard)
        if .n < 8 then .
        else .v = (.v/256|floor) | .n -= 8 | .ph = "sc" | _step end

      elif $ph == "sc" then   # copy rem literal bytes from input stream
        if   .rem == 0 then (if .bf==1 then .ph="gf" else .ph="db" end) | _step
        elif .n   <  8 then .
        else (.v%256) as $b | .v = (.v/256|floor) | .n -= 8 | .rem -= 1 |
          _emit($b) | _step
        end

      ## ── FIXED HUFFMAN BLOCK (BTYPE=01, RFC 1951 §3.2.6) ───────────────────

      elif $ph == "fl" then   # decode lit/len symbol
        _decode(.ll) |
        if   .sym == null then .
        elif .sym  < 256  then _emit(.sym) | _step
        elif .sym == 256  then (if .bf==1 then .ph="gf" else .ph="db" end) | _step
        else  # length symbol 257–285
          $lbase[.sym - 257] as $lb | .rem = $lb[1] | .br = $lb[0] | .ph = "fe" | _step
        end

      elif $ph == "fe" then   # extra length bits
        if .n < .br then .
        else
          (if .br > 0
           then .rem += (.v % $p2[.br]) | .v = (.v/$p2[.br]|floor) | .n -= .br
           else .
           end) |
          .ph = "fd" | _step
        end

      elif $ph == "fd" then   # decode distance symbol
        _decode(.dd) |
        if .sym == null then .
        else $dbase[.sym] as $db | .bd = $db[1] | .br2 = $db[0] | .ph = "fde" | _step end

      elif $ph == "fde" then  # extra distance bits
        if .n < .br2 then .
        else
          (if .br2 > 0
           then .bd += (.v % $p2[.br2]) | .v = (.v/$p2[.br2]|floor) | .n -= .br2
           else .
           end) |
          .ph = "fc" | _step
        end

      elif $ph == "fc" then   # copy back-reference (fixed)
        ((.w|length) - .bd) as $src |
        if $src < 0
        then error("gzip: back-reference distance \(.bd) exceeds window \(.w|length)")
        else
          [ range(.rem) as $i | .w[$src + ($i % .bd)] ] as $copy |
          .out += $copy | .w += $copy |
          (if (.w|length) > 40000 then .w = .w[-32768:] else . end) |
          .ph = "fl" | _step
        end

      ## ── DYNAMIC HUFFMAN BLOCK (BTYPE=10, RFC 1951 §3.2.7) ─────────────────

      elif $ph == "dy0" then  # HLIT(5) + HDIST(5) + HCLEN(4) = 14 bits
        if .n < 14 then .
        else
          (.v%32) as $hl | ((.v/32|floor)%32) as $hd | ((.v/1024|floor)%16) as $hc |
          .v = (.v/16384|floor) | .n -= 14 |
          .hlit = $hl+257 | .hdist = $hd+1 | .lnum = .hlit + .hdist |
          .lbuf = [range(19) | 0] | .lpos = 0 | .rem = $hc+4 |
          .ph = "dy1" | _step
        end

      elif $ph == "dy1" then  # HCLEN+4 code-length alphabet entries (3 bits each)
        if .rem == 0 then
          .ll = _gz_htable(.lbuf) | .lbuf = [] | .prev = 0 | .ph = "dy2" | _step
        elif .n < 3 then .
        else
          .lbuf[$clord[.lpos]] = (.v%8) |
          .v = (.v/8|floor) | .n -= 3 | .lpos += 1 | .rem -= 1 | _step
        end

      elif $ph == "dy2" then  # decode main code lengths using CL tree
        if (.lbuf|length) >= .lnum then
          .ll = _gz_htable(.lbuf[:.hlit]) |
          .dd = _gz_htable(.lbuf[.hlit:(.hlit+.hdist)]) |
          .lbuf = [] | .ph = "dl" | _step
        else
          _decode(.ll) |
          if   .sym == null then .
          elif .sym <= 15   then .lbuf += [.sym] | .prev = .sym | _step
          elif .sym == 16   then .ph = "dy2_a" | _step
          elif .sym == 17   then .ph = "dy2_b" | _step
          elif .sym == 18   then .ph = "dy2_c" | _step
          else error("gzip: invalid CL symbol \(.sym)")
          end
        end

      elif $ph == "dy2_a" then  # CL 16: repeat previous × (3 + 2-bit count)
        if .n < 2 then .
        else ((.v%4)+3) as $c | .v = (.v/4|floor) | .n -= 2 |
          .prev as $p | .lbuf += [range($c) | $p] | .ph = "dy2" | _step
        end

      elif $ph == "dy2_b" then  # CL 17: repeat zero × (3 + 3-bit count)
        if .n < 3 then .
        else ((.v%8)+3) as $c | .v = (.v/8|floor) | .n -= 3 |
          .lbuf += [range($c) | 0] | .ph = "dy2" | _step
        end

      elif $ph == "dy2_c" then  # CL 18: repeat zero × (11 + 7-bit count)
        if .n < 7 then .
        else ((.v%128)+11) as $c | .v = (.v/128|floor) | .n -= 7 |
          .lbuf += [range($c) | 0] | .ph = "dy2" | _step
        end

      ## ── DYNAMIC HUFFMAN: SYMBOL DECODE ────────────────────────────────────

      elif $ph == "dl" then   # decode lit/len symbol (dynamic)
        _decode(.ll) |
        if   .sym == null then .
        elif .sym  < 256  then _emit(.sym) | _step
        elif .sym == 256  then (if .bf==1 then .ph="gf" else .ph="db" end) | _step
        else
          $lbase[.sym - 257] as $lb | .rem = $lb[1] | .br = $lb[0] | .ph = "de" | _step
        end

      elif $ph == "de" then   # extra length bits (dynamic)
        if .n < .br then .
        else
          (if .br > 0
           then .rem += (.v % $p2[.br]) | .v = (.v/$p2[.br]|floor) | .n -= .br
           else .
           end) |
          .ph = "dd" | _step
        end

      elif $ph == "dd" then   # decode distance symbol (dynamic)
        _decode(.dd) |
        if .sym == null then .
        else $dbase[.sym] as $db | .bd = $db[1] | .br2 = $db[0] | .ph = "dde" | _step end

      elif $ph == "dde" then  # extra distance bits (dynamic)
        if .n < .br2 then .
        else
          (if .br2 > 0
           then .bd += (.v % $p2[.br2]) | .v = (.v/$p2[.br2]|floor) | .n -= .br2
           else .
           end) |
          .ph = "dc" | _step
        end

      elif $ph == "dc" then   # copy back-reference (dynamic)
        ((.w|length) - .bd) as $src |
        if $src < 0
        then error("gzip: back-reference distance \(.bd) exceeds window \(.w|length)")
        else
          [ range(.rem) as $i | .w[$src + ($i % .bd)] ] as $copy |
          .out += $copy | .w += $copy |
          (if (.w|length) > 40000 then .w = .w[-32768:] else . end) |
          .ph = "dl" | _step
        end

      ## ── GZIP FOOTER (RFC 1952 §2.3.1) ─────────────────────────────────────
      # CRC32 and ISIZE are not verified; the 8 footer bytes are consumed and discarded.

      elif $ph == "gf" then   # align to byte boundary, then skip 8-byte footer
        _align | .rem = 8 | .ph = "gfs" | _step

      elif $ph == "gfs" then  # skip rem footer bytes
        if   .rem == 0 then .ph = "end"
        elif .n   <  8 then .
        else .v = (.v/256|floor) | .n -= 8 | .rem -= 1 | _step
        end

      else .  # "end" or unknown phase: drain is complete
      end;

    _step;

  foreach gen as $byte (
    {v:0, n:0, w:[], ph:"h0", out:[], flg:0, hq:[],
     rem:0, bf:0, sym:null, ll:null, dd:null,
     br:0, bd:0, br2:0, lbuf:[], lnum:0,
     hlit:0, hdist:0, lpos:0, prev:0};
    .out = [] | .v += ($byte * $p2[.n]) | .n += 8 | _gz_drain;
    .out[]
  );
