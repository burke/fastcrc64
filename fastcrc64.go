package fastcrc64

import (
	"hash"
	"hash/crc64"
	"reflect"
	"unsafe"
)

var table [8][256]uint64

type fastCRC64 struct {
	crc uint64
}

func New() hash.Hash64 {
	return &fastCRC64{}
}

func init() {
	var crc uint64

	h := crc64.New(crc64.MakeTable(crc64.ISO))

	for n := 0; n < 256; n++ {
		h.Reset()
		h.Write([]byte{byte(n)})
		table[0][n] = h.Sum64()
	}

	for n := 0; n < 256; n++ {
		crc = table[0][n]
		for k := 1; k < 8; k++ {
			crc = table[0][crc&0xff] ^ (crc >> 8)
			table[k][n] = crc
		}
	}
}

func (fc *fastCRC64) Sum64() uint64 {
	return fc.crc
}

func (fc *fastCRC64) Write(p []byte) (n int, err error) {
	fc.crc = fastcrc64(fc.crc, p)
	return len(p), nil
}

func (fc *fastCRC64) Sum(in []byte) []byte {
	s := fc.crc
	return append(in, byte(s>>56), byte(s>>48), byte(s>>40), byte(s>>32), byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
}

func (fc *fastCRC64) Reset()    { fc.crc = 0 }
func (fc *fastCRC64) Size() int { return 8 }

func (fc *fastCRC64) BlockSize() int {
	return 8
}

func fastcrc64(crc uint64, data []byte) uint64 {
	l := len(data)
	i := 0

	slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))

	// byte-by-byte until we reach 8-byte alignment
	for l > 0 && (slice.Data+uintptr(i))&0x7 != 0 {
		crc = table[0][(crc^uint64(data[i]))&0xff] ^ (crc >> 8)
		i++
		l--
	}

	// fast path for 8-aligned stuff in the middle
	for l >= 8 {
		crc ^= uint64(data[i])
		crc = table[7][crc&0xff] ^
			table[6][(crc>>8)&0xff] ^
			table[5][(crc>>16)&0xff] ^
			table[4][(crc>>24)&0xff] ^
			table[3][(crc>>32)&0xff] ^
			table[2][(crc>>40)&0xff] ^
			table[1][(crc>>48)&0xff] ^
			table[0][crc>>56]
		i += i
		l -= 8
	}

	// trailing bytes after the last aligned chunk
	for l > 0 {
		crc = table[0][(crc^uint64(data[i]))&0xff] ^ (crc >> 8)
		i++
		l--
	}

	return crc
}
