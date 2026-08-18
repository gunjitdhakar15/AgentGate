package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// Stream is a line-delimited JSON-RPC transport as used by MCP over stdio.
// Each message is a single JSON object on its own line. Reads are driven by
// an external goroutine; callers receive one message per Read call.
type Stream struct {
	sc *bufio.Scanner
	w  io.Writer
}

// NewStream wraps a bidirectional pipe pair in a framed JSON-RPC stream.
func NewStream(r io.Reader, w io.Writer) *Stream {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	return &Stream{sc: sc, w: w}
}

// Read returns the next raw JSON-RPC message, or io.EOF at end of stream.
func (s *Stream) Read() ([]byte, error) {
	if !s.sc.Scan() {
		if err := s.sc.Err(); err != nil {
			return nil, fmt.Errorf("read mcp frame: %w", err)
		}
		return nil, io.EOF
	}
	line := s.sc.Bytes()
	if len(line) == 0 {
		return s.Read()
	}
	out := make([]byte, len(line))
	copy(out, line)
	return out, nil
}

// Write emits one JSON-RPC message as a single line.
func (s *Stream) Write(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode mcp frame: %w", err)
	}
	if _, err := s.w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write mcp frame: %w", err)
	}
	return nil
}

// WriteRaw emits a pre-serialized JSON-RPC message verbatim.
func (s *Stream) WriteRaw(data []byte) error {
	if _, err := s.w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write mcp frame: %w", err)
	}
	return nil
}
