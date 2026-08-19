package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Entry is one immutable audit record. Secrets are redacted before the
// record is persisted, so the log is safe to share.
type Entry struct {
	TS        time.Time       `json:"ts"`
	Kind      string          `json:"kind"` // request | response | blocked | error
	RequestID string          `json:"request_id,omitempty"`
	Method    string          `json:"method"`
	Tool      string          `json:"tool,omitempty"`
	Args      json.RawMessage `json:"args,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Decision  string          `json:"decision,omitempty"`
	Duration  time.Duration   `json:"duration_ns,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// Store appends JSONL audit records to a file, flush-per-write so the log
// survives process death.
type Store struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// Open opens (creating if needed) the audit log at path.
func Open(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Store{f: f, path: path}, nil
}

// Log appends one record.
func (s *Store) Log(e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode audit entry: %w", err)
	}
	if _, err := s.f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return s.f.Sync()
}

// Path returns the log file location (used by tests and tooling).
func (s *Store) Path() string { return s.path }

// Close flushes and closes the log.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// Replay reads the log back in order. Useful for incident reviews and tests.
func Replay(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for len(data) > 0 {
		var line []byte
		if i := indexOfNewline(data); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue // skip corrupt lines rather than fail replay
		}
		out = append(out, e)
	}
	return out, nil
}

func indexOfNewline(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i
		}
	}
	return -1
}
