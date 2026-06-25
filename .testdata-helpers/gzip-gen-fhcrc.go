// gzip-gen-fhcrc: generates a base64-encoded gzip with an FHCRC header field
// usage: go run gzip-gen-fhcrc.go [content]
// FHCRC is the lower 16 bits of CRC32 over all header bytes preceding it (RFC 1952 §2.3.1)
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
	w.writeBit(1) // BFINAL
	w.writeBit(1) // BTYPE = 01 (fixed Huffman), LSB-first
	w.writeBit(0)
	for _, b := range data {
		if b <= 143 {
			w.writeCode(int(b)+48, 8)
		} else {
			w.writeCode(int(b)+256, 9)
		}
	}
	w.writeCode(0, 7) // EOB: symbol 256, 7-bit code 0000000
	return w.flush()
}

func main() {
	content := []byte("Hello, world!")
	if len(os.Args) > 1 {
		content = []byte(os.Args[1])
	}

	hdr := []byte{
		0x1f, 0x8b, // ID1, ID2
		0x08,       // CM = deflate
		0x02,       // FLG = FHCRC
		0, 0, 0, 0, // MTIME = 0
		0x00, // XFL
		0x03, // OS = Unix
	}
	// lower 16 bits of CRC32 of all header bytes preceding the FHCRC field
	hdrSum := crc32.ChecksumIEEE(hdr)
	hdr = append(hdr, byte(hdrSum), byte(hdrSum>>8))
	hdr = append(hdr, fixedDeflate(content)...)

	sum := crc32.ChecksumIEEE(content)
	size := uint32(len(content))
	hdr = append(hdr,
		byte(sum), byte(sum>>8), byte(sum>>16), byte(sum>>24),
		byte(size), byte(size>>8), byte(size>>16), byte(size>>24),
	)

	fmt.Println(base64.StdEncoding.EncodeToString(hdr))
}
