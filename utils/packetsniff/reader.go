package packetsniff

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"
)

// Reader is a bounds checked little endian reader over a raw packet payload.
//
// Every method records the first error it hits and turns into a no-op after
// that, so a caller can read a whole structure and check Err once at the end
// instead of branching on every field.
type Reader struct {
	Data []byte
	Pos  int
	Err  error
}

func NewReader(data []byte) *Reader {
	return &Reader{Data: data}
}

func (r *Reader) fail(format string, args ...any) {
	if r.Err == nil {
		r.Err = fmt.Errorf(format, args...)
	}
}

func (r *Reader) need(n int) []byte {
	if r.Err != nil {
		return nil
	}
	if n < 0 || r.Pos+n > len(r.Data) {
		r.fail("truncated at %d: need %d bytes, have %d", r.Pos, n, len(r.Data)-r.Pos)
		return nil
	}
	b := r.Data[r.Pos : r.Pos+n]
	r.Pos += n
	return b
}

// Remaining returns the number of unread bytes.
func (r *Reader) Remaining() int {
	if r.Err != nil {
		return 0
	}
	return len(r.Data) - r.Pos
}

func (r *Reader) U8() uint8 {
	if b := r.need(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *Reader) I8() int8 { return int8(r.U8()) }

func (r *Reader) Bool() bool { return r.U8() != 0 }

// BoolStrict additionally rejects a byte that is neither 0 nor 1. Vanilla
// writes plain booleans, so anything else means the offset is wrong.
func (r *Reader) BoolStrict() bool {
	b := r.U8()
	if r.Err != nil {
		return false
	}
	if b > 1 {
		r.fail("invalid bool %d at %d", b, r.Pos-1)
		return false
	}
	return b == 1
}

func (r *Reader) U16() uint16 {
	if b := r.need(2); b != nil {
		return binary.LittleEndian.Uint16(b)
	}
	return 0
}

func (r *Reader) I16() int16 { return int16(r.U16()) }

func (r *Reader) U32() uint32 {
	if b := r.need(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

func (r *Reader) I32() int32 { return int32(r.U32()) }

func (r *Reader) U64() uint64 {
	if b := r.need(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}

func (r *Reader) I64() int64 { return int64(r.U64()) }

func (r *Reader) F32() float32 {
	return math.Float32frombits(r.U32())
}

// VarU32 reads a varuint32. A varint longer than 5 bytes is rejected: this is
// what the client does as well and it keeps a corrupt payload from swallowing
// the rest of the packet.
func (r *Reader) VarU32() uint32 {
	var v uint32
	for i := 0; i < 5; i++ {
		b := r.U8()
		if r.Err != nil {
			return 0
		}
		v |= uint32(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return v
		}
	}
	r.fail("varuint32 too long at %d", r.Pos)
	return 0
}

// VarU64 reads a varuint64 in at most 10 bytes.
func (r *Reader) VarU64() uint64 {
	var v uint64
	for i := 0; i < 10; i++ {
		b := r.U8()
		if r.Err != nil {
			return 0
		}
		v |= uint64(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return v
		}
	}
	r.fail("varuint64 too long at %d", r.Pos)
	return 0
}

func (r *Reader) ZigZag32() int32 {
	v := r.VarU32()
	return int32(v>>1) ^ -int32(v&1)
}

func (r *Reader) ZigZag64() int64 {
	v := r.VarU64()
	return int64(v>>1) ^ -int64(v&1)
}

// MaxString bounds string reads. A packet carrying a longer string is either
// corrupt or parsed under the wrong hypothesis.
const MaxString = 1 << 15

func (r *Reader) String() string {
	n := r.VarU32()
	if r.Err != nil {
		return ""
	}
	if n > MaxString {
		r.fail("string too long: %d at %d", n, r.Pos)
		return ""
	}
	b := r.need(int(n))
	if b == nil {
		return ""
	}
	if !utf8.Valid(b) {
		r.fail("string not utf8 at %d", r.Pos-int(n))
		return ""
	}
	return string(b)
}

func (r *Reader) ShortString() string {
	n := r.I16()
	if r.Err != nil {
		return ""
	}
	if n < 0 || int(n) > MaxString {
		r.fail("short string bad length %d at %d", n, r.Pos)
		return ""
	}
	b := r.need(int(n))
	if b == nil {
		return ""
	}
	if !utf8.Valid(b) {
		r.fail("string not utf8 at %d", r.Pos-int(n))
		return ""
	}
	return string(b)
}

// Vec3f reads three float32 and checks they are finite and inside the range a
// real world position can have. This is the cheapest sanity check available
// when deciding whether a byte offset is still correct.
func (r *Reader) Vec3f() [3]float32 {
	var v [3]float32
	for i := range v {
		v[i] = r.F32()
	}
	for i, f := range v {
		if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) || math.Abs(float64(f)) > 3.2e7 {
			r.fail("vec3f[%d] implausible: %v", i, f)
			return v
		}
	}
	return v
}

func (r *Reader) Vec3i() [3]int32 {
	var v [3]int32
	for i := range v {
		v[i] = r.ZigZag32()
	}
	return v
}

// Skip advances n bytes.
func (r *Reader) Skip(n int) {
	r.need(n)
}

// SkipNBT skips one network little endian NBT tag, computing its length only.
// Implemented by hand instead of decoding into a map: the sniffer is interested
// in the byte offset after the tag, and allocating any tree would be wasted work
// on every entity packet.
func (r *Reader) SkipNBT() {
	r.skipNBTNamed(true)
}

func (r *Reader) skipNBTNamed(named bool) {
	tag := r.U8()
	if r.Err != nil {
		return
	}
	if tag == 0 { // TAG_End, no name and no payload
		if named {
			// A bare End outside of a compound is legal as an empty root.
			return
		}
		return
	}
	if named {
		n := r.VarU32()
		if r.Err != nil {
			return
		}
		if n > MaxString {
			r.fail("nbt name too long: %d", n)
			return
		}
		r.Skip(int(n))
	}
	r.skipNBTPayload(tag, true)
}

func (r *Reader) skipNBTPayload(tag uint8, namedPayload bool) {
	switch tag {
	case 0: // end
	case 1: // byte
		r.Skip(1)
	case 2: // short: fixed little endian, unlike int and long
		r.Skip(2)
	case 3: // int: zigzag varint
		r.ZigZag32()
	case 4: // long: zigzag varint
		r.ZigZag64()
	case 5: // float
		r.Skip(4)
	case 6: // double
		r.Skip(8)
	case 7: // byte array
		n := r.ZigZag32()
		if r.Err == nil && (n < 0 || n > MaxString*16) {
			r.fail("nbt byte array bad length: %d", n)
			return
		}
		r.Skip(int(n))
	case 8: // string
		n := r.VarU32()
		if r.Err == nil && n > MaxString {
			r.fail("nbt string too long: %d", n)
			return
		}
		r.Skip(int(n))
	case 9: // list
		elem := r.U8()
		n := r.ZigZag32()
		if r.Err != nil {
			return
		}
		if n < 0 || n > MaxString*16 {
			r.fail("nbt list bad length: %d", n)
			return
		}
		for i := int32(0); i < n && r.Err == nil; i++ {
			r.skipNBTPayload(elem, false)
		}
	case 10: // compound
		for r.Err == nil {
			inner := r.U8()
			if r.Err != nil || inner == 0 {
				return
			}
			n := r.VarU32()
			if r.Err != nil {
				return
			}
			if n > MaxString {
				r.fail("nbt name too long: %d", n)
				return
			}
			r.Skip(int(n))
			r.skipNBTPayload(inner, true)
		}
	case 11: // int array
		n := r.ZigZag32()
		if r.Err == nil && (n < 0 || n > MaxString*16) {
			r.fail("nbt int array bad length: %d", n)
			return
		}
		for i := int32(0); i < n && r.Err == nil; i++ {
			r.ZigZag32()
		}
	case 12: // long array
		n := r.ZigZag32()
		if r.Err == nil && (n < 0 || n > MaxString*16) {
			r.fail("nbt long array bad length: %d", n)
			return
		}
		for i := int32(0); i < n && r.Err == nil; i++ {
			r.ZigZag64()
		}
	default:
		r.fail("unknown nbt tag %d at %d", tag, r.Pos)
	}
}
