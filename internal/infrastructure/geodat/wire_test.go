package geodat

import (
	"bytes"
	"math"
	"slices"
	"testing"
)

func TestVarint(t *testing.T) {
	nines := bytes.Repeat([]byte{0xff}, maxVarintLen-1)
	tests := []struct {
		name  string
		in    []byte
		wantV uint64
		wantN int
	}{
		{"one byte", []byte{0x05}, 5, 1},
		{"two bytes", []byte{0xac, 0x02}, 300, 2},
		{"largest", slices.Concat(nines, []byte{0x01}), math.MaxUint64, maxVarintLen},
		{"overflow in the tenth byte", slices.Concat(nines, []byte{0x02}), 0, 0},
		{"eleven bytes", slices.Concat(nines, []byte{0x81, 0x00}), 0, 0},
		{"truncated", []byte{0x80}, 0, 0},
		{"empty", nil, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if v, n := varint(tt.in); v != tt.wantV || n != tt.wantN {
				t.Fatalf("varint(%x) = %d, %d; want %d, %d", tt.in, v, n, tt.wantV, tt.wantN)
			}
		})
	}
}
