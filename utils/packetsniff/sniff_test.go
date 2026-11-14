package packetsniff

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/s2"
	"github.com/sandertv/gophertunnel/minecraft/nbt"
)

// enc is a minimal writer that mirrors the gophertunnel encoders, so tests can
// build payloads for a chosen hypothesis instead of hardcoding hex dumps.
type enc struct{ b []byte }

func (e *enc) u8(v uint8) *enc { e.b = append(e.b, v); return e }

func (e *enc) u16(v uint16) *enc {
	e.b = binary.LittleEndian.AppendUint16(e.b, v)
	return e
}

func (e *enc) i16(v int16) *enc { return e.u16(uint16(v)) }

func (e *enc) u32(v uint32) *enc {
	e.b = binary.LittleEndian.AppendUint32(e.b, v)
	return e
}

func (e *enc) i32(v int32) *enc { return e.u32(uint32(v)) }

func (e *enc) i64(v int64) *enc {
	e.b = binary.LittleEndian.AppendUint64(e.b, uint64(v))
	return e
}

func (e *enc) f32(v float32) *enc { return e.u32(math.Float32bits(v)) }

func (e *enc) varu32(v uint32) *enc {
	for v >= 0x80 {
		e.b = append(e.b, byte(v)|0x80)
		v >>= 7
	}
	e.b = append(e.b, byte(v))
	return e
}

func (e *enc) varu64(v uint64) *enc {
	for v >= 0x80 {
		e.b = append(e.b, byte(v)|0x80)
		v >>= 7
	}
	e.b = append(e.b, byte(v))
	return e
}

func (e *enc) zz32(v int32) *enc { return e.varu32(uint32(v)<<1 ^ uint32(v>>31)) }
func (e *enc) zz64(v int64) *enc { return e.varu64(uint64(v)<<1 ^ uint64(v>>63)) }

func (e *enc) str(s string) *enc {
	e.varu32(uint32(len(s)))
	e.b = append(e.b, s...)
	return e
}

func (e *enc) vec3(x, y, z float32) *enc { return e.f32(x).f32(y).f32(z) }

func (e *enc) raw(b []byte) *enc { e.b = append(e.b, b...); return e }

// item writes one item stack under h. id 0 is air.
func (e *enc) item(h Hypothesis, id int32, count uint16) *enc {
	if h.Item == ItemLayoutV1 {
		e.zz32(id)
		if id == 0 && h.Air == AirShort {
			return e
		}
		e.u16(count).varu32(0).u8(0).zz32(0).varu32(0)
		return e
	}
	e.i16(int16(id))
	if id == 0 && h.Air == AirShort {
		return e
	}
	e.u16(count).varu32(0).u8(0).varu32(0).varu32(0)
	return e
}

// metaEntry is one metadata dictionary entry with a prebuilt value.
type metaEntry struct {
	key   uint32
	typ   uint32
	value func(e *enc)
}

func (e *enc) metadata(h Hypothesis, entries []metaEntry) *enc {
	e.varu32(uint32(len(entries)))
	for _, m := range entries {
		e.varu32(m.key).varu32(m.typ)
		if h.LegacyType {
			e.u8(uint8(m.typ))
		}
		m.value(e)
	}
	return e
}

func (e *enc) properties() *enc { return e.varu32(0).varu32(0) }

func (e *enc) abilityData() *enc {
	e.i64(1).u8(1).u8(0)
	e.varu32(1)
	e.u16(1).u32(0).u32(0).f32(0.05).f32(0.05).f32(0.1)
	return e
}

func (e *enc) links() *enc { return e.varu32(0) }

func (e *enc) passenger(h Hypothesis) *enc {
	if h.PassengerOfBlock {
		e.u8(0)
	}
	return e
}

func testMetadata() []metaEntry {
	return []metaEntry{
		{key: 0, typ: 7, value: func(e *enc) { e.zz64(0) }},
		{key: 1, typ: 3, value: func(e *enc) { e.f32(20) }},
		{key: 4, typ: 4, value: func(e *enc) { e.str("Steve") }},
		{key: 38, typ: 3, value: func(e *enc) { e.f32(1) }},
	}
}

func buildAddItemActor(h Hypothesis, air bool) []byte {
	var id int32 = 5
	if air {
		id = 0
	}
	e := &enc{}
	e.zz64(7).varu64(8)
	e.item(h, id, 1)
	e.vec3(1, 64, 2).vec3(0, 0, 0)
	e.metadata(h, testMetadata())
	e.u8(0)
	return e.b
}

func buildSetActorData(h Hypothesis) []byte {
	e := &enc{}
	e.varu64(3)
	e.metadata(h, testMetadata())
	e.properties()
	e.varu64(100)
	return e.b
}

func buildAddActor(h Hypothesis) []byte {
	e := &enc{}
	e.zz64(7).varu64(8).str("minecraft:zombie")
	e.vec3(1, 64, 2).vec3(0, 0, 0)
	e.f32(0).f32(0).f32(0).f32(0)
	e.varu32(0) // attributes
	e.metadata(h, testMetadata())
	e.properties()
	e.links()
	e.passenger(h)
	return e.b
}

func buildAddPlayer(h Hypothesis, air bool) []byte {
	var id int32 = 5
	if air {
		id = 0
	}
	e := &enc{}
	e.raw(make([]byte, 16))
	e.str("Steve").varu64(1).str("")
	e.vec3(0, 64, 0).vec3(0, 0, 0)
	e.f32(0).f32(0).f32(0)
	e.item(h, id, 1)
	e.zz32(1)
	e.metadata(h, testMetadata())
	e.properties()
	e.abilityData()
	e.links()
	e.passenger(h)
	e.str("device").i32(7)
	return e.b
}

func buildMovePlayer(h Hypothesis, mode uint8, teleport bool) []byte {
	e := &enc{}
	e.varu64(1).vec3(0, 64, 0).f32(0).f32(0).f32(0)
	e.u8(mode).u8(1).varu64(0)
	if h.TeleportOption {
		if teleport {
			e.u8(1).i32(2).i32(63)
		} else {
			e.u8(0)
		}
	} else if mode == 2 {
		e.i32(2).i32(63)
	}
	e.varu64(500)
	return e.b
}

func winnerOf(t *testing.T, o Observation) Outcome {
	t.Helper()
	if o.Winner == nil {
		for _, out := range o.Outcomes {
			t.Logf("%s consumed=%d err=%v", out.Hyp, out.Consumed, out.Err)
		}
		t.Fatalf("%s: no hypothesis matched (%d bytes)", o.Name, o.Length)
	}
	if o.Ambiguous {
		t.Fatalf("%s: ambiguous, %d hypotheses matched", o.Name, len(o.OutcomesOK()))
	}
	return *o.Winner
}

func TestItemAndAirLayouts(t *testing.T) {
	hyps := []Hypothesis{
		{Item: ItemLayoutInstance, Air: AirFull},
		{Item: ItemLayoutInstance, Air: AirShort},
		{Item: ItemLayoutV1, Air: AirShort},
	}
	for _, h := range hyps {
		for _, air := range []bool{false, true} {
			// An air stack only discriminates when the item is air.
			if !air && h.Air == AirShort && h.Item == ItemLayoutV1 {
				continue
			}
			payload := buildAddItemActor(h, air)
			o := Probe(idAddItemActor, payload, false, time.Now())
			w := winnerOf(t, o)
			if w.Hyp.Item != h.Item {
				t.Fatalf("air=%t: got %s, want item=%s", air, w.Hyp, h.Item)
			}
			// The air mode is only observable on an actually empty stack.
			if air && w.Hyp.Air != h.Air {
				t.Fatalf("air=%t: got %s, want air=%s", air, w.Hyp, h.Air)
			}
			if air && w.Facts.ItemBytes != 8 && h.Air == AirFull {
				t.Fatalf("air stack should occupy 8 bytes, got %d", w.Facts.ItemBytes)
			}
			if air && h.Air == AirShort && w.Facts.ItemBytes != 2 && h.Item == ItemLayoutInstance {
				t.Fatalf("short air stack should occupy 2 bytes, got %d", w.Facts.ItemBytes)
			}
		}
	}
}

func TestLegacyType(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		h := Hypothesis{Item: ItemLayoutInstance, Air: AirFull, LegacyType: legacy}
		o := Probe(idSetActorData, buildSetActorData(h), false, time.Now())
		w := winnerOf(t, o)
		if w.Hyp.LegacyType != legacy {
			t.Fatalf("legacy=%t: got %s", legacy, w.Hyp)
		}
		if legacy && w.Facts.MetaLegacyMatch != w.Facts.MetaEntries {
			t.Fatalf("legacy selector should equal the type, got %d/%d", w.Facts.MetaLegacyMatch, w.Facts.MetaEntries)
		}
	}
}

func TestTeleport(t *testing.T) {
	cases := []struct {
		h        Hypothesis
		mode     uint8
		teleport bool
	}{
		{Hypothesis{TeleportOption: true}, 2, true},
		{Hypothesis{TeleportOption: true}, 0, false},
		{Hypothesis{TeleportOption: false}, 2, true},
		{Hypothesis{TeleportOption: false}, 0, false},
	}
	for _, c := range cases {
		o := Probe(idMovePlayer, buildMovePlayer(c.h, c.mode, c.teleport), false, time.Now())
		w := winnerOf(t, o)
		if w.Hyp.TeleportOption != c.h.TeleportOption {
			t.Fatalf("mode=%d teleport=%t: got %s", c.mode, c.teleport, w.Hyp)
		}
	}
}

func TestAddPlayer(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		for _, pax := range []bool{true, false} {
			for _, air := range []bool{true, false} {
				h := Hypothesis{
					Item: ItemLayoutInstance, Air: AirFull,
					LegacyType: legacy, PassengerOfBlock: pax,
				}
				o := Probe(idAddPlayer, buildAddPlayer(h, air), false, time.Now())
				w := winnerOf(t, o)
				if w.Hyp.LegacyType != legacy || w.Hyp.PassengerOfBlock != pax {
					t.Fatalf("legacy=%t pax=%t: got %s", legacy, pax, w.Hyp)
				}
			}
		}
	}
}

func TestAddActor(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		for _, pax := range []bool{true, false} {
			h := Hypothesis{Item: ItemLayoutInstance, Air: AirFull, LegacyType: legacy, PassengerOfBlock: pax}
			o := Probe(idAddActor, buildAddActor(h), false, time.Now())
			w := winnerOf(t, o)
			if w.Hyp.LegacyType != legacy || w.Hyp.PassengerOfBlock != pax {
				t.Fatalf("legacy=%t pax=%t: got %s", legacy, pax, w.Hyp)
			}
		}
	}
}

func TestNoMatchReportsCleanly(t *testing.T) {
	payload := buildSetActorData(Hypothesis{ItemLayoutInstance, AirFull, true, false, false})
	payload = append(payload, 0xde, 0xad) // trailing garbage
	o := Probe(idSetActorData, payload, false, time.Now())
	if o.Winner != nil {
		t.Fatalf("expected no match, got %s", o.Winner.Hyp)
	}
	if line := Line(o); line == "" {
		t.Fatal("expected a report line")
	}
	if short := Short(o); !strings.HasPrefix(short, "no match") {
		t.Fatalf("unexpected short verdict %q", short)
	}
}

func TestNBTSkipMatchesEncoder(t *testing.T) {
	tags := []any{
		map[string]any{
			"name":  "hello",
			"count": int32(42),
			"big":   int64(-7),
			"short": int16(3),
			"flag":  byte(1),
			"ratio": float32(0.5),
			"pos":   [3]int32{1, -2, 3},
			"blob":  [4]byte{1, 2, 3, 4},
			"list":  []any{int32(1), int32(2), int32(3)},
		},
		map[string]any{
			"nested": map[string]any{
				"inner": []any{
					map[string]any{"a": int32(1)},
					map[string]any{"b": int32(2)},
				},
			},
			"empty": []any{},
			"longs": []int64{1, 2},
		},
	}
	for i, v := range tags {
		data, err := nbt.MarshalEncoding(v, nbt.NetworkLittleEndian)
		if err != nil {
			t.Fatalf("case %d: encode: %s", i, err)
		}
		// Append a sentinel so a short skip is visible.
		data = append(data, 0xAA, 0xBB)
		r := NewReader(data)
		r.SkipNBT()
		if r.Err != nil {
			t.Fatalf("case %d: skip: %s", i, r.Err)
		}
		if r.Pos != len(data)-2 {
			t.Fatalf("case %d: skipped %d of %d bytes", i, r.Pos, len(data)-2)
		}
	}
}

func TestAnalyzePcap(t *testing.T) {
	h := Hypothesis{Item: ItemLayoutInstance, Air: AirFull}
	body := buildAddItemActor(h, true)

	// pcap2 header + empty pack archive + one record.
	var f bytes.Buffer
	f.WriteString("BTCP")
	binary.Write(&f, binary.LittleEndian, uint32(5))
	binary.Write(&f, binary.LittleEndian, uint64(0))

	payload := (&enc{}).varu32(idAddItemActor).raw(body).b
	comp := s2.EncodeBetter(nil, payload)
	binary.Write(&f, binary.LittleEndian, uint32(0xAAAAAAAA))
	binary.Write(&f, binary.LittleEndian, uint32(len(comp)))
	f.WriteByte(0) // server to client
	binary.Write(&f, binary.LittleEndian, uint64(time.Now().UnixMilli()))
	f.Write(comp)
	binary.Write(&f, binary.LittleEndian, uint32(0xBBBBBBBB))

	path := filepath.Join(t.TempDir(), "capture.pcap2")
	if err := os.WriteFile(path, f.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	sum, n, err := AnalyzePcap(path, &Writer{}, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 probed packet, got %d", n)
	}
	found := false
	for _, v := range sum.Verdicts() {
		if v.Dim == DimAir && v.Value == "air-full" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an air-full verdict, got %+v", sum.Verdicts())
	}
}

func TestSplitHeader(t *testing.T) {
	// A plain id.
	id, body, err := SplitHeader(append([]byte{byte(idAddPlayer)}, 0xAA, 0xBB))
	if err != nil || id != idAddPlayer || len(body) != 2 {
		t.Fatalf("id=%d body=%d err=%v", id, len(body), err)
	}

	// The id shares a varuint with the sub client ids in the high bits.
	raw := (&enc{}).varu32(idAddPlayer | 1<<10).b
	id, body, err = SplitHeader(append(raw, 0x01))
	if err != nil || id != idAddPlayer || len(body) != 1 {
		t.Fatalf("sub client: id=%d body=%d err=%v", id, len(body), err)
	}

	if _, _, err := SplitHeader(nil); err == nil {
		t.Fatal("expected an error for an empty header")
	}
}

func TestWriterJSON(t *testing.T) {
	var buf bytes.Buffer
	w := &Writer{Out: &buf}
	h := Hypothesis{Item: ItemLayoutInstance, Air: AirFull, LegacyType: true}
	o := Probe(idSetActorData, buildSetActorData(h), false, time.Now())
	if err := w.Write(o); err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("invalid json: %s", err)
	}
	if rec["name"] != "set_actor_data" {
		t.Fatalf("unexpected name %v", rec["name"])
	}
	verdict, ok := rec["verdict"].(map[string]any)
	if !ok || verdict["legacy_type"] != true {
		t.Fatalf("unexpected verdict %v", rec["verdict"])
	}
	if rec["matched"] != true {
		t.Fatalf("expected matched")
	}
}
