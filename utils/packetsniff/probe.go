package packetsniff

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Dim is one ambiguous aspect of the wire format that the sniffer tries to
// resolve from captured traffic.
type Dim int

const (
	// DimItem is the item stack encoding.
	DimItem Dim = iota
	// DimAir is whether an empty stack carries the trailing fields.
	DimAir
	// DimLegacy is the extra selector byte in a metadata entry.
	DimLegacy
	// DimTeleport is the leading bool of the move_player teleport body.
	DimTeleport
	// DimPassenger is the optional block passenger record on add_player and
	// add_actor.
	DimPassenger
)

func (d Dim) String() string {
	switch d {
	case DimItem:
		return "item-layout"
	case DimAir:
		return "air-layout"
	case DimLegacy:
		return "metadata-legacy-type"
	case DimTeleport:
		return "teleport-option"
	case DimPassenger:
		return "passenger-of-block"
	}
	return "unknown"
}

// Value reports what h assumes for this dimension.
func (d Dim) Value(h Hypothesis) string {
	switch d {
	case DimItem:
		return h.Item.String()
	case DimAir:
		if h.Item == ItemLayoutV1 {
			// Item v1 is defined to short circuit on air, so the dimension
			// carries no information there.
			return "n/a"
		}
		return h.Air.String()
	case DimLegacy:
		if h.LegacyType {
			return "present"
		}
		return "absent"
	case DimTeleport:
		if h.TeleportOption {
			return "present"
		}
		return "absent"
	case DimPassenger:
		if h.PassengerOfBlock {
			return "present"
		}
		return "absent"
	}
	return "?"
}

// DimsFor returns the dimensions that a packet can actually discriminate.
func DimsFor(id uint32) []Dim {
	switch id {
	case idAddPlayer:
		return []Dim{DimItem, DimAir, DimLegacy, DimPassenger}
	case idAddActor:
		return []Dim{DimLegacy, DimPassenger}
	case idAddItemActor:
		return []Dim{DimItem, DimAir, DimLegacy}
	case idMovePlayer:
		return []Dim{DimTeleport}
	case idMobEquipment, idMobArmourEquipment:
		return []Dim{DimItem, DimAir}
	case idSetActorData:
		return []Dim{DimLegacy}
	}
	return nil
}

// Outcome is the result of parsing one payload under one hypothesis.
type Outcome struct {
	Hyp      Hypothesis
	Consumed int
	Err      error
	Facts    Facts
}

// Observation is the result of probing one captured payload.
type Observation struct {
	ID        uint32
	Name      string
	Length    int
	ToServer  bool
	Time      time.Time
	Outcomes  []Outcome
	Winner    *Outcome
	Ambiguous bool

	raw []byte
}

// Probe parses payload under every hypothesis that could apply to packetID and
// decides which ones consume it exactly.
func Probe(packetID uint32, payload []byte, toServer bool, received time.Time) Observation {
	name := Names[packetID]
	if name == "" {
		name = fmt.Sprintf("packet_%d", packetID)
	}
	o := Observation{
		ID:       packetID,
		Name:     name,
		Length:   len(payload),
		ToServer: toServer,
		Time:     received,
		raw:      payload,
	}

	var ok []Outcome
	for _, h := range hypothesesFor(packetID) {
		facts, consumed, err := Parse(packetID, payload, h)
		out := Outcome{Hyp: h, Consumed: consumed, Err: err, Facts: facts}
		o.Outcomes = append(o.Outcomes, out)
		if err == nil && consumed == len(payload) {
			ok = append(ok, out)
		}
	}

	// Hypotheses that differ only in a dimension the payload cannot show are
	// not real ambiguity: for a non empty stack, air handling changes nothing,
	// so both air modes parse identically. Collapse those before deciding.
	if len(ok) > 1 {
		ref := observableKey(ok[0])
		same := true
		for _, other := range ok[1:] {
			if observableKey(other) != ref {
				same = false
				break
			}
		}
		if same {
			ok = ok[:1]
		}
	}

	switch len(ok) {
	case 1:
		o.Winner = &ok[0]
	case 0:
		// Nothing matched: leave Winner nil so the summary counts it as
		// unexplained instead of guessing.
	default:
		o.Ambiguous = true
		o.Winner = &ok[0]
	}
	return o
}

// hypothesesFor builds the cartesian product of the dimensions that apply to a
// packet. Dimensions that do not apply are pinned to their real value, which
// keeps the search space small.
func hypothesesFor(id uint32) []Hypothesis {
	items := []ItemLayout{ItemLayoutInstance}
	airs := []AirMode{AirFull}
	legacys := []bool{false}
	teleports := []bool{false}
	passengers := []bool{false}

	switch id {
	case idAddPlayer:
		items = []ItemLayout{ItemLayoutInstance, ItemLayoutV1}
		airs = []AirMode{AirFull, AirShort}
		legacys = []bool{true, false}
		passengers = []bool{false, true}
	case idAddActor:
		items = []ItemLayout{ItemLayoutInstance}
		legacys = []bool{true, false}
		passengers = []bool{false, true}
	case idAddItemActor:
		items = []ItemLayout{ItemLayoutInstance, ItemLayoutV1}
		airs = []AirMode{AirFull, AirShort}
		legacys = []bool{true, false}
	case idMovePlayer:
		teleports = []bool{true, false}
	case idMobEquipment, idMobArmourEquipment:
		items = []ItemLayout{ItemLayoutInstance, ItemLayoutV1}
		airs = []AirMode{AirFull, AirShort}
	case idSetActorData:
		legacys = []bool{true, false}
	}

	var out []Hypothesis
	for _, it := range items {
		for _, air := range airs {
			for _, legacy := range legacys {
				for _, tp := range teleports {
					for _, pax := range passengers {
						out = append(out, Hypothesis{
							Item:             it,
							Air:              air,
							LegacyType:       legacy,
							TeleportOption:   tp,
							PassengerOfBlock: pax,
						})
					}
				}
			}
		}
	}
	return out
}

// Summary aggregates observations into a per dimension verdict.
type Summary struct {
	Total     int
	Ambiguous int
	Unmatched int
	Matched   int

	Counts map[Dim]map[string]int

	LegacyEntries int
	LegacyMatches int

	PerPacket map[uint32]*PacketSummary
}

// PacketSummary counts observations per packet type.
type PacketSummary struct {
	Total     int
	Matched   int
	Ambiguous int
	Unmatched int
}

func NewSummary() *Summary {
	return &Summary{
		Counts:    map[Dim]map[string]int{},
		PerPacket: map[uint32]*PacketSummary{},
	}
}

// Add folds one observation into the summary. Ambiguous and unmatched
// observations are counted but never vote, so a single odd frame cannot flip a
// verdict.
func (s *Summary) Add(o Observation) {
	s.Total++

	ps := s.PerPacket[o.ID]
	if ps == nil {
		ps = &PacketSummary{}
		s.PerPacket[o.ID] = ps
	}
	ps.Total++

	switch {
	case o.Ambiguous:
		s.Ambiguous++
		ps.Ambiguous++
		return
	case o.Winner == nil:
		s.Unmatched++
		ps.Unmatched++
		return
	}

	s.Matched++
	ps.Matched++

	for _, d := range DimsFor(o.ID) {
		v := d.Value(o.Winner.Hyp)
		if v == "n/a" {
			continue
		}
		m := s.Counts[d]
		if m == nil {
			m = map[string]int{}
			s.Counts[d] = m
		}
		m[v]++
	}

	if o.Winner.Hyp.LegacyType {
		s.LegacyEntries += o.Winner.Facts.MetaEntries
		s.LegacyMatches += o.Winner.Facts.MetaLegacyMatch
	}
}

// Verdict is the winning value of one dimension.
type Verdict struct {
	Dim   Dim
	Value string
	Wins  int
	Total int
}

// Verdicts returns the most likely value per dimension, sorted by dimension.
func (s *Summary) Verdicts() []Verdict {
	var out []Verdict
	for d, m := range s.Counts {
		var best string
		var bestN int
		total := 0
		for v, n := range m {
			total += n
			if n > bestN {
				best, bestN = v, n
			}
		}
		out = append(out, Verdict{Dim: d, Value: best, Wins: bestN, Total: total})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dim < out[j].Dim })
	return out
}

// Lines renders the verdicts as human readable conclusions.
func (s *Summary) Lines() []string {
	var lines []string
	for _, v := range s.Verdicts() {
		pct := 100.0
		if v.Total > 0 {
			pct = float64(v.Wins) * 100 / float64(v.Total)
		}
		lines = append(lines, fmt.Sprintf("%-22s %-16s %d/%d (%.1f%%)",
			v.Dim.String(), v.Value, v.Wins, v.Total, pct))
	}
	if s.LegacyEntries > 0 {
		lines = append(lines, fmt.Sprintf("%-22s selector byte equals type in %d/%d entries",
			"metadata-sanity", s.LegacyMatches, s.LegacyEntries))
	}
	return lines
}

// Conclusion renders a one line summary suitable for the top of a report.
func (s *Summary) Conclusion() string {
	var parts []string
	for _, v := range s.Verdicts() {
		switch v.Dim {
		case DimItem:
			parts = append(parts, fmt.Sprintf("item stack uses %s", v.Value))
		case DimAir:
			if v.Value == "air-full" {
				parts = append(parts, "empty stacks still carry all trailing fields (8 bytes)")
			} else if v.Value == "air-short" {
				parts = append(parts, "empty stacks stop after the network id")
			}
		case DimLegacy:
			if v.Value == "present" {
				parts = append(parts, "metadata entries carry a legacy_type byte")
			} else {
				parts = append(parts, "metadata entries do not carry a legacy_type byte")
			}
		case DimTeleport:
			if v.Value == "present" {
				parts = append(parts, "move_player always prefixes teleport with a bool")
			} else {
				parts = append(parts, "move_player switches on mode without a bool")
			}
		case DimPassenger:
			if v.Value == "present" {
				parts = append(parts, "add_player/add_actor carry an optional passenger record")
			} else {
				parts = append(parts, "add_player/add_actor end after the links")
			}
		}
	}
	if len(parts) == 0 {
		return "no evidence yet"
	}
	return strings.Join(parts, "; ")
}

// Text renders the whole verdict block, used by both the live handler and the
// offline pcap mode so the two produce identical reports.
func (s *Summary) Text() string {
	var b strings.Builder
	b.WriteString("verdict: " + s.Conclusion() + "\n")
	for _, l := range s.Lines() {
		b.WriteString(l + "\n")
	}
	fmt.Fprintf(&b, "packets: total=%d matched=%d ambiguous=%d unmatched=%d\n",
		s.Total, s.Matched, s.Ambiguous, s.Unmatched)
	return b.String()
}

// observableKey identifies what a payload can actually distinguish. The air
// mode only matters when the stack is empty; every other dimension always
// changes the byte layout.
func observableKey(o Outcome) string {
	key := o.Hyp.Item.String()
	if o.Facts.ItemIsAir {
		key += "|" + o.Hyp.Air.String()
	}
	return key + fmt.Sprintf("|%t|%t|%t", o.Hyp.LegacyType, o.Hyp.TeleportOption, o.Hyp.PassengerOfBlock)
}
