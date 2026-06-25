// gzip-gen-fixed-huffman: generates a base64-encoded gzip with a BTYPE=01 (fixed Huffman) deflate block
// usage: go run gzip-gen-fixed-huffman.go [content]
// content defaults to "Hello, world!"
package main

import (
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"os"
)

type bitWriter struct {
	buf   []byte
	cur   byte
	nbits int
}

func (w *bitWriter) writeBit(b int) {
	if b != 0 {
		w.cur |= 1 << w.nbits
	}
	w.nbits++
	if w.nbits == 8 {
		w.buf = append(w.buf, w.cur)
		w.cur = 0
		w.nbits = 0
	}
}

// writeCode writes a Huffman code MSB-first into the bit stream
func (w *bitWriter) writeCode(code, bits int) {
	for i := bits - 1; i >= 0; i-- {
		w.writeBit((code >> i) & 1)
	}
}

func (w *bitWriter) flush() []byte {
	if w.nbits > 0 {
		w.buf = append(w.buf, w.cur)
		w.cur = 0
		w.nbits = 0
	}
	return w.buf
}

func fixedDeflate(data []byte) []byte {
	w := &bitWriter{}
	w.writeBit(1) // BFINAL = 1
	w.writeBit(1) // BTYPE = 01 (fixed Huffman), transmitted LSB-first
	w.writeBit(0)
	for _, b := range data {
		if b <= 143 {
			w.writeCode(int(b)+48, 8) // RFC 1951 §3.2.6: codes 00110000..10111111
		} else {
			w.writeCode(int(b)+256, 9) // codes 110010000..111111111
		}
	}
	w.writeCode(0, 7) // EOB: symbol 256, 7-bit code 0000000
	return w.flush()
}

func gzipWrap(deflated, content []byte) []byte {
	out := []byte{
		0x1f, 0x8b, // ID1, ID2
		0x08,       // CM = deflate
		0x00,       // FLG = none
		0, 0, 0, 0, // MTIME = 0
		0x00, // XFL
		0x03, // OS = Unix
	}
	out = append(out, deflated...)
	sum := crc32.ChecksumIEEE(content)
	size := uint32(len(content))
	out = append(out,
		byte(sum), byte(sum>>8), byte(sum>>16), byte(sum>>24),
		byte(size), byte(size>>8), byte(size>>16), byte(size>>24),
	)
	return out
}

func main() {
	content := []byte("Hello, world!")
	if len(os.Args) > 1 {
		content = []byte(os.Args[1])
	}
	fmt.Println(base64.StdEncoding.EncodeToString(gzipWrap(fixedDeflate(content), content)))
}
