package geodat

import (
	"errors"
	"fmt"
)

// ErrMalformed marks input that is not a valid protobuf stream.
var ErrMalformed = errors.New("malformed geo data")

// Protobuf wire types (https://protobuf.dev/programming-guides/encoding/).
const (
	wireVarint = 0
	wireI64    = 1
	wireLen    = 2
	wireI32    = 5
)

// field is one decoded protobuf field. Only varint and length-delimited values
// are kept; the geo formats use nothing else.
type field struct {
	num    int
	varint uint64
	bytes  []byte
}

// fields iterates over the top-level fields of a message. The yielded bytes
// alias data; nothing is copied.
func fields(data []byte, yield func(field) error) error {
	for len(data) > 0 {
		key, n := varint(data)
		if n == 0 {
			return fmt.Errorf("%w: truncated field key", ErrMalformed)
		}
		data = data[n:]
		f := field{num: int(key >> 3)}

		switch key & 7 {
		case wireVarint:
			v, n := varint(data)
			if n == 0 {
				return fmt.Errorf("%w: truncated varint in field %d", ErrMalformed, f.num)
			}
			f.varint, data = v, data[n:]
		case wireLen:
			size, n := varint(data)
			if n == 0 || uint64(len(data)-n) < size {
				return fmt.Errorf("%w: truncated bytes in field %d", ErrMalformed, f.num)
			}
			f.bytes, data = data[n:n+int(size)], data[n+int(size):]
		case wireI64:
			if len(data) < 8 {
				return fmt.Errorf("%w: truncated fixed64 in field %d", ErrMalformed, f.num)
			}
			data = data[8:]
			continue
		case wireI32:
			if len(data) < 4 {
				return fmt.Errorf("%w: truncated fixed32 in field %d", ErrMalformed, f.num)
			}
			data = data[4:]
			continue
		default:
			return fmt.Errorf("%w: wire type %d in field %d", ErrMalformed, key&7, f.num)
		}

		if err := yield(f); err != nil {
			return err
		}
	}
	return nil
}

// maxVarintLen is the longest encoding of a 64-bit varint.
const maxVarintLen = 10

// varint decodes a base-128 varint; n is 0 when data ends inside it or the
// value overflows 64 bits. The last of ten bytes carries only the 64th bit: 63
// are taken by the nine before it.
func varint(data []byte) (v uint64, n int) {
	for i, b := range data {
		if i == maxVarintLen-1 && b > 1 {
			return 0, 0
		}
		v |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}
