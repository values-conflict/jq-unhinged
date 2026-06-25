// gzip-btype-check: prints the BTYPE of every deflate block in one or more base64-encoded gzip streams
// usage: go run gzip-btype-check.go <base64-gzip> [...]
package main

import (
	"encoding/base64"
	"fmt"
	"os"
)

var (
	lenExtra  = [29]int{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}
	distExtra = [30]int{0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13}
	clOrder   = [19]int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

	fixedLL, fixedDist []huffEntry
)

type huffEntry struct {
	code, length, symbol int
}

func buildTable(lengths []int) []huffEntry {
	maxLen := 0
	for _, l := range lengths {
		if l > maxLen {
			maxLen = l
		}
	}
	blCount := make([]int, maxLen+1)
	for _, l := range lengths {
		if l > 0 {
			blCount[l]++
		}
	}
	nextCode := make([]int, maxLen+2)
	code := 0
	for bits := 1; bits <= maxLen; bits++ {
		code = (code + blCount[bits-1]) << 1
		nextCode[bits] = code
	}
	var table []huffEntry
	for sym, l := range lengths {
		if l > 0 {
			c := nextCode[l]
			nextCode[l]++
			table = append(table, huffEntry{code: c, length: l, symbol: sym})
		}
	}
	return table
}

func init() {
	ll := make([]int, 288)
	for i := 0; i <= 143; i++ {
		ll[i] = 8
	}
	for i := 144; i <= 255; i++ {
		ll[i] = 9
	}
	for i := 256; i <= 279; i++ {
		ll[i] = 7
	}
	for i := 280; i <= 287; i++ {
		ll[i] = 8
	}
	fixedLL = buildTable(ll)

	dist := make([]int, 30)
	for i := range dist {
		dist[i] = 5
	}
	fixedDist = buildTable(dist)
}

type bitReader struct {
	data  []byte
	bpos  int
	buf   uint64
	nbits int
}

func (r *bitReader) readBit() int {
	if r.nbits == 0 {
		r.buf = uint64(r.data[r.bpos])
		r.bpos++
		r.nbits = 8
	}
	b := int(r.buf & 1)
	r.buf >>= 1
	r.nbits--
	return b
}

func (r *bitReader) readLSB(n int) int {
	v := 0
	for i := 0; i < n; i++ {
		v |= r.readBit() << i
	}
	return v
}

func (r *bitReader) align() {
	r.buf = 0
	r.nbits = 0
}

func hDecode(r *bitReader, table []huffEntry) int {
	code := 0
	for bits := 1; bits <= 15; bits++ {
		code = (code << 1) | r.readBit()
		for _, e := range table {
			if e.length == bits && e.code == code {
				return e.symbol
			}
		}
	}
	panic("invalid Huffman code")
}

func skipRef(r *bitReader, sym int, dist []huffEntry) {
	r.readLSB(lenExtra[sym-257])
	r.readLSB(distExtra[hDecode(r, dist)])
}

func scanToEOB(r *bitReader, ll, dist []huffEntry) {
	for {
		sym := hDecode(r, ll)
		if sym == 256 {
			return
		}
		if sym > 256 {
			skipRef(r, sym, dist)
		}
	}
}

func checkBtypes(data []byte) (btypes []int, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%v", p)
		}
	}()

	if len(data) < 10 || data[0] != 0x1f || data[1] != 0x8b {
		return nil, fmt.Errorf("not a gzip stream")
	}
	if data[2] != 8 {
		return nil, fmt.Errorf("unsupported CM %d", data[2])
	}
	flg := data[3]
	pos := 10

	if flg&0x04 != 0 {
		xlen := int(data[pos]) | int(data[pos+1])<<8
		pos += 2 + xlen
	}
	if flg&0x08 != 0 {
		for data[pos] != 0 {
			pos++
		}
		pos++
	}
	if flg&0x10 != 0 {
		for data[pos] != 0 {
			pos++
		}
		pos++
	}
	if flg&0x02 != 0 {
		pos += 2
	}

	r := &bitReader{data: data[pos:]}

	for {
		bfinal := r.readBit()
		btype := r.readLSB(2)
		btypes = append(btypes, btype)

		switch btype {
		case 0:
			r.align()
			length := r.readLSB(16)
			r.readLSB(16) // NLEN
			// after align + two readLSB(16) calls, nbits==0; advance bpos directly
			r.bpos += length
		case 1:
			scanToEOB(r, fixedLL, fixedDist)
		case 2:
			hlit := r.readLSB(5) + 257
			hdist := r.readLSB(5) + 1
			hclen := r.readLSB(4) + 4

			clLens := make([]int, 19)
			for i := 0; i < hclen; i++ {
				clLens[clOrder[i]] = r.readLSB(3)
			}
			clTable := buildTable(clLens)

			total := hlit + hdist
			lens := make([]int, total)
			for i := 0; i < total; {
				sym := hDecode(r, clTable)
				switch {
				case sym < 16:
					lens[i] = sym
					i++
				case sym == 16:
					n := r.readLSB(2) + 3
					for j := 0; j < n; j++ {
						lens[i] = lens[i-1]
						i++
					}
				case sym == 17:
					i += r.readLSB(3) + 3
				case sym == 18:
					i += r.readLSB(7) + 11
				}
			}

			scanToEOB(r, buildTable(lens[:hlit]), buildTable(lens[hlit:]))
		default:
			return nil, fmt.Errorf("reserved BTYPE 11")
		}

		if bfinal == 1 {
			break
		}
	}

	return btypes, nil
}

func btypeStr(bt int) string {
	switch bt {
	case 0:
		return "BTYPE=00 (stored)"
	case 1:
		return "BTYPE=01 (fixed Huffman)"
	case 2:
		return "BTYPE=10 (dynamic Huffman)"
	}
	return fmt.Sprintf("BTYPE=%02b (unknown)", bt)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <base64-gzip> [...]\n", os.Args[0])
		os.Exit(1)
	}

	multi := len(os.Args) > 2
	ok := true

	for _, arg := range os.Args[1:] {
		raw, err := base64.StdEncoding.DecodeString(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: base64: %v\n", err)
			ok = false
			continue
		}
		bts, err := checkBtypes(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			ok = false
			continue
		}
		if multi {
			disp := arg
			if len(disp) > 28 {
				disp = disp[:28] + "..."
			}
			fmt.Printf("%s: ", disp)
		}
		for i, bt := range bts {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(btypeStr(bt))
		}
		fmt.Println()
	}

	if !ok {
		os.Exit(1)
	}
}
