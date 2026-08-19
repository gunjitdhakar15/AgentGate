package web

import (
	"testing"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
)

func entry(kind, tool string) audit.Entry {
	return audit.Entry{TS: time.Now(), Kind: kind, Tool: tool}
}

func TestDashboardCounters(t *testing.T) {
	d := New()
	d.handleEntry(entry("request", ""))
	d.handleEntry(entry("request", ""))
	d.handleEntry(entry("response", "read_file"))
	d.handleEntry(entry("blocked", "shell"))
	d.handleEntry(entry("blocked", "shell"))
	d.handleEntry(entry("redacted", "shell"))
	d.handleEntry(entry("protocol", ""))

	s := d.snapshotObject()
	if s.Counters["total"] != 2 {
		t.Errorf("total = %d, want 2", s.Counters["total"])
	}
	if s.Counters["allowed"] != 1 {
		t.Errorf("allowed = %d, want 1", s.Counters["allowed"])
	}
	if s.Counters["blocked"] != 2 {
		t.Errorf("blocked = %d, want 2", s.Counters["blocked"])
	}
	if s.Counters["redacted"] != 1 {
		t.Errorf("redacted = %d, want 1", s.Counters["redacted"])
	}
	if s.Counters["protocolError"] != 1 {
		t.Errorf("protocolError = %d, want 1", s.Counters["protocolError"])
	}
	if len(s.Recent) != 7 {
		t.Errorf("recent = %d, want 7", len(s.Recent))
	}
	if s.Tools["shell"].Blocked != 2 {
		t.Errorf("shell blocked = %d, want 2", s.Tools["shell"].Blocked)
	}
	if s.Tools["read_file"].Allowed != 1 {
		t.Errorf("read_file allowed = %d, want 1", s.Tools["read_file"].Allowed)
	}
	if s.Tools["shell"].Redacted != 1 {
		t.Errorf("shell redacted = %d, want 1", s.Tools["shell"].Redacted)
	}
}

func TestDashboardBroadcast(t *testing.T) {
	d := New()
	ch, done := d.Subscribe()
	defer done()

	e := entry("blocked", "shell")
	d.handleEntry(e)

	select {
	case ev := <-ch:
		if ev.Type != "entry" {
			t.Errorf("event type = %q, want entry", ev.Type)
		}
		got := ev.Data.(audit.Entry)
		if got.Tool != "shell" {
			t.Errorf("event tool = %q, want shell", got.Tool)
		}
	case <-time.After(time.Second):
		t.Fatal("no event received on subscriber channel")
	}
}

func TestDashboardSlowSubscriberDropped(t *testing.T) {
	d := New()
	// Never drain the channel; the broadcast must not block.
	_, done := d.Subscribe()
	defer done()
	for i := 0; i < 300; i++ {
		d.handleEntry(entry("request", ""))
	}
	s := d.snapshotObject()
	if s.Counters["total"] != 300 {
		t.Errorf("total = %d, want 300", s.Counters["total"])
	}
}
