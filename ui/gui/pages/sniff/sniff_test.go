package sniff

import (
	"testing"
	"time"

	"github.com/bedrock-tool/bedrocktool/ui/messages"
)

// The page is fed by the proxy goroutine, so these exercise the aggregation
// without any gio context: no layout, no window, just the event contract.
func TestPageCollectsObservations(t *testing.T) {
	p := New(nil).(*Page)

	p.HandleEvent(&messages.EventSniffObservation{
		Time: time.Now(), Name: "add_player", Length: 144,
		Verdict: "empty 8B · instance/full", Matched: true,
	})
	p.HandleEvent(&messages.EventSniffObservation{
		Time: time.Now(), Name: "add_actor", Length: 91,
		Verdict: "meta 4 · sel 4/4", Ambiguous: true,
	})
	p.HandleEvent(&messages.EventSniffSummary{
		Text: "verdict: ok", Total: 2, Matched: 1, Ambiguous: 1, Finished: true,
	})

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(p.rows))
	}
	if p.rows[0].name != "add_player" || !p.rows[0].matched {
		t.Fatalf("unexpected first row %+v", p.rows[0])
	}
	if !p.rows[1].ambiguous {
		t.Fatalf("expected the second row to be ambiguous")
	}
	if p.total != 2 || p.matched != 1 || p.ambig != 1 || !p.finished {
		t.Fatalf("unexpected totals %d/%d/%d finished=%t", p.total, p.matched, p.ambig, p.finished)
	}
	if p.text != "verdict: ok" {
		t.Fatalf("unexpected verdict text %q", p.text)
	}
}

func TestPageDropsOldestRows(t *testing.T) {
	p := New(nil).(*Page)
	for i := 0; i < maxRows+10; i++ {
		p.HandleEvent(&messages.EventSniffObservation{Name: "add_player", Length: i})
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.rows) != maxRows {
		t.Fatalf("expected the row window to stay at %d, got %d", maxRows, len(p.rows))
	}
	if p.rows[0].length != 10 {
		t.Fatalf("expected the oldest rows to be dropped, first is %d", p.rows[0].length)
	}
}

func TestPageTakesListenAddress(t *testing.T) {
	p := New(nil).(*Page)
	p.HandleEvent(&messages.EventConnectStateUpdate{
		State:      messages.ConnectStateListening,
		ListenAddr: "0.0.0.0:19132",
	})

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listen != "0.0.0.0:19132" {
		t.Fatalf("unexpected listen address %q", p.listen)
	}
}
