package packetsniff

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Writer emits observations as json lines and, optionally, as human readable
// lines through a printf compatible sink.
type Writer struct {
	Out     io.Writer
	Log     func(format string, args ...any)
	Verbose bool

	// OnObservation is called for every observation after it has been written,
	// so a live view can render the same data that goes to the log and file.
	// It runs on the proxy goroutine and must not block.
	OnObservation func(o Observation)
}

type jsonHypothesis struct {
	Item           string `json:"item"`
	Air            string `json:"air"`
	LegacyType     bool   `json:"legacy_type"`
	TeleportOption bool   `json:"teleport_option"`
	Passenger      bool   `json:"passenger_of_block"`
}

type jsonOutcome struct {
	Hyp      jsonHypothesis `json:"hypothesis"`
	Consumed int            `json:"consumed"`
	OK       bool           `json:"ok"`
	Error    string         `json:"error,omitempty"`
}

type jsonFacts struct {
	ItemNetworkID  int32 `json:"item_network_id"`
	ItemBytes      int   `json:"item_bytes"`
	MetaEntries    int   `json:"meta_entries"`
	MetaLegacyHits int   `json:"meta_legacy_hits"`
	MetaCompound   int   `json:"meta_compound"`
	MoveMode       uint8 `json:"move_mode,omitempty"`
	TeleportBool   *bool `json:"teleport_option_value,omitempty"`
}

type jsonObservation struct {
	Time      string          `json:"time"`
	Dir       string          `json:"dir"`
	ID        uint32          `json:"id"`
	Name      string          `json:"name"`
	Length    int             `json:"length"`
	Verdict   *jsonHypothesis `json:"verdict,omitempty"`
	Ambiguous bool            `json:"ambiguous,omitempty"`
	Matched   bool            `json:"matched"`
	Facts     jsonFacts       `json:"facts"`
	Hex       string          `json:"hex"`
	Outcomes  []jsonOutcome   `json:"outcomes"`
}

func toJSONHyp(h Hypothesis) jsonHypothesis {
	return jsonHypothesis{
		Item:           h.Item.String(),
		Air:            h.Air.String(),
		LegacyType:     h.LegacyType,
		TeleportOption: h.TeleportOption,
		Passenger:      h.PassengerOfBlock,
	}
}

// Write appends one observation to the json stream and prints a one line
// summary. A single observation never fails the whole capture.
func (w *Writer) Write(o Observation) error {
	if w.Out != nil {
		rec := jsonObservation{
			Time:      o.Time.Format(time.RFC3339Nano),
			Dir:       dirName(o.ToServer),
			ID:        o.ID,
			Name:      o.Name,
			Length:    o.Length,
			Ambiguous: o.Ambiguous,
			Matched:   o.Winner != nil && !o.Ambiguous,
			Facts: jsonFacts{
				ItemNetworkID:  o.winnerFacts().ItemNetworkID,
				ItemBytes:      o.winnerFacts().ItemBytes,
				MetaEntries:    o.winnerFacts().MetaEntries,
				MetaLegacyHits: o.winnerFacts().MetaLegacyMatch,
				MetaCompound:   o.winnerFacts().MetaCompound,
				MoveMode:       o.winnerFacts().MoveMode,
			},
			Hex: hex.EncodeToString(o.rawHex()),
		}
		if o.Winner != nil {
			h := toJSONHyp(o.Winner.Hyp)
			rec.Verdict = &h
			if o.Winner.Hyp.TeleportOption || o.Winner.Facts.TeleportRead {
				v := o.Winner.Facts.TeleportPresent
				rec.Facts.TeleportBool = &v
			}
		}
		for _, out := range o.Outcomes {
			jo := jsonOutcome{
				Hyp:      toJSONHyp(out.Hyp),
				Consumed: out.Consumed,
				OK:       out.Err == nil && out.Consumed == o.Length,
			}
			if out.Err != nil {
				jo.Error = out.Err.Error()
			}
			rec.Outcomes = append(rec.Outcomes, jo)
		}
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := w.Out.Write(append(b, '\n')); err != nil {
			return err
		}
	}

	if w.Log != nil {
		w.Log("%s", Line(o))
		if w.Verbose {
			for _, l := range Detail(o) {
				w.Log("%s", l)
			}
		}
	}
	if w.OnObservation != nil {
		w.OnObservation(o)
	}
	return nil
}

// Line renders the compact per packet line.
func Line(o Observation) string {
	head := fmt.Sprintf("[%s] %-22s len=%-4d", dirName(o.ToServer), o.Name, o.Length)
	switch {
	case o.Ambiguous:
		return head + " -> AMBIGUOUS (" + strconv.Itoa(len(o.OutcomesOK())) + " exact)"
	case o.Winner == nil:
		return head + " -> NO MATCH  " + o.closest()
	}

	f := o.Winner.Facts
	extra := ""
	if f.HasItem {
		extra += fmt.Sprintf(" | item=%d(%dB)", f.ItemNetworkID, f.ItemBytes)
	}
	if f.MetaEntries > 0 {
		extra += fmt.Sprintf(" meta=%d", f.MetaEntries)
		if o.Winner.Hyp.LegacyType {
			extra += fmt.Sprintf(" legacy=%d/%d", f.MetaLegacyMatch, f.MetaEntries)
		}
	}
	if o.Winner.Facts.TeleportRead {
		extra += fmt.Sprintf(" teleport(bool=%t)", o.Winner.Facts.TeleportPresent)
	}
	return head + " -> " + o.Winner.Hyp.String() + extra
}

// Detail renders every hypothesis that was tried, for the verbose mode.
func Detail(o Observation) []string {
	lines := make([]string, 0, len(o.Outcomes))
	for i, out := range o.Outcomes {
		status := "FAIL"
		note := ""
		if out.Err != nil {
			note = out.Err.Error()
		} else if out.Consumed == o.Length {
			status = "EXACT"
		} else {
			note = fmt.Sprintf("left %d bytes", o.Length-out.Consumed)
		}
		lines = append(lines, fmt.Sprintf("    #%02d %-10s %-10s legacy=%-5t tp=%-5t pax=%-5t consumed=%-4d %s %s",
			i, out.Hyp.Item, out.Hyp.Air, out.Hyp.LegacyType, out.Hyp.TeleportOption,
			out.Hyp.PassengerOfBlock, out.Consumed, status, note))
	}
	return lines
}

func (o Observation) rawHex() []byte {
	const max = 96
	if len(o.raw) <= max {
		return o.raw
	}
	return o.raw[:max]
}

func (o Observation) winnerFacts() Facts {
	if o.Winner == nil {
		return Facts{}
	}
	return o.Winner.Facts
}

// OutcomesOK returns the outcomes that consumed the payload exactly.
func (o Observation) OutcomesOK() []Outcome {
	var ok []Outcome
	for _, out := range o.Outcomes {
		if out.Err == nil && out.Consumed == o.Length {
			ok = append(ok, out)
		}
	}
	return ok
}

// closest returns the hypothesis that got furthest, used when nothing matched.
func (o Observation) closest() string {
	best := -1
	idx := 0
	for i, out := range o.Outcomes {
		if out.Consumed > best {
			best, idx = out.Consumed, i
		}
	}
	if best < 0 {
		return ""
	}
	out := o.Outcomes[idx]
	msg := "none consumed anything"
	if out.Err != nil {
		msg = out.Err.Error()
	} else if out.Consumed != o.Length {
		msg = fmt.Sprintf("left %d bytes", o.Length-out.Consumed)
	}
	return fmt.Sprintf("(best %s: %s)", out.Hyp, msg)
}

func dirName(toServer bool) string {
	if toServer {
		return "c2s"
	}
	return "s2c"
}

// Short renders the verdict as one compact line for the gui table, which has
// no room for the full hypothesis dump. It keeps every dimension the packet
// could actually discriminate, so a reader can still tell the versions apart.
func Short(o Observation) string {
	switch {
	case o.Ambiguous:
		return fmt.Sprintf("ambiguous: %d parses consume it exactly", len(o.OutcomesOK()))
	case o.Winner == nil:
		return "no match  " + o.closest()
	}

	f := o.Winner.Facts
	h := o.Winner.Hyp
	var parts []string

	if f.HasItem {
		if f.ItemIsAir {
			parts = append(parts, fmt.Sprintf("empty %dB", f.ItemBytes))
		} else {
			parts = append(parts, fmt.Sprintf("item %d %dB", f.ItemNetworkID, f.ItemBytes))
		}
	}
	if f.MetaEntries > 0 {
		parts = append(parts, fmt.Sprintf("meta %d", f.MetaEntries))
		if h.LegacyType {
			parts = append(parts, fmt.Sprintf("sel %d/%d", f.MetaLegacyMatch, f.MetaEntries))
		}
	}
	if f.TeleportRead {
		parts = append(parts, fmt.Sprintf("tp bool=%t", f.TeleportPresent))
	}

	if f.HasItem {
		parts = append(parts, shortLayout(h))
	}
	if h.LegacyType && f.MetaEntries == 0 {
		parts = append(parts, "sel")
	}
	if h.TeleportOption && !f.TeleportRead {
		parts = append(parts, "tp option")
	}
	if h.PassengerOfBlock {
		parts = append(parts, "pax")
	}
	return strings.Join(parts, " · ")
}

// shortLayout names the resolved item encoding, e.g. "instance/full".
func shortLayout(h Hypothesis) string {
	if h.Item == ItemLayoutV1 {
		return "v1"
	}
	if h.Air == AirShort {
		return "instance/short"
	}
	return "instance/full"
}
