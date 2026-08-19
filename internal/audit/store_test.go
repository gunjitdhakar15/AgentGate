package audit

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreLogAndReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := []Entry{
		{TS: time.Now(), Kind: "request", RequestID: "1", Method: "tools/call", Tool: "shell"},
		{TS: time.Now(), Kind: "blocked", RequestID: "2", Method: "tools/call", Tool: "shell", Decision: "dangerous command"},
		{TS: time.Now(), Kind: "response", RequestID: "3", Method: "tools/call", Tool: "read_file", Result: json.RawMessage(`{"ok":true}`)},
	}
	for _, e := range entries {
		if err := s.Log(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := Replay(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("replayed %d entries, want 3", len(got))
	}
	if got[1].Decision != "dangerous command" || got[1].Kind != "blocked" {
		t.Fatalf("bad replayed entry: %+v", got[1])
	}
	if got[2].Result == nil || len(got[2].Result) == 0 {
		t.Fatal("response result must survive replay")
	}
}

func TestReplaySkipsCorruptLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, _ := Open(path)
	_ = s.Log(Entry{TS: time.Now(), Kind: "request", Method: "ping"})
	_ = s.Close()
	// Append garbage after close, simulate a torn write.
	f, _ := Open(path)
	_, _ = f.f.Write([]byte("this is not json\n"))
	_ = f.Close()

	got, err := Replay(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 clean entry intact, got %d", len(got))
	}
}
