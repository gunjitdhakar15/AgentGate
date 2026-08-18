package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestObjectKindClassification(t *testing.T) {
	cases := []struct {
		payload string
		want    Kind
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`, KindRequest},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, KindNotification},
		{`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`, KindResponse},
		{`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}`, KindResponse},
		{`{"nope":true}`, KindUnknown},
		{`not json`, KindUnknown},
	}
	for _, c := range cases {
		if got := ObjectKind([]byte(c.payload)); got != c.want {
			t.Errorf("ObjectKind(%s) = %v, want %v", c.payload, got, c.want)
		}
	}
}

func TestStreamRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	s := NewStream(strings.NewReader(""), &buf)
	req := Request{JSONRPC: "2.0", ID: json.RawMessage(`42`), Method: "ping"}
	if err := s.Write(req); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	want := `{"jsonrpc":"2.0","id":42,"method":"ping"}`
	if got != want {
		t.Fatalf("framing mismatch: got %s want %s", got, want)
	}

	r := NewStream(strings.NewReader(got+"\n"), io.Discard)
	line, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(line)) != want {
		t.Fatalf("read mismatch: %s", line)
	}
}

func TestRequestIDString(t *testing.T) {
	r := Request{ID: json.RawMessage(`"abc"`)}
	if r.IDString() != "abc" {
		t.Fatalf("string id: %v", r.IDString())
	}
	r = Request{ID: json.RawMessage(`7`)}
	if r.IDString() != "7" {
		t.Fatalf("numeric id: %v", r.IDString())
	}
	r = Request{ID: json.RawMessage(`null`)}
	if r.HasID() {
		t.Fatal("null id must count as absent")
	}
	r = Request{} // no id at all
	if r.HasID() {
		t.Fatal("missing id must count as absent")
	}
}

func TestBlockedResultShape(t *testing.T) {
	r := BlockedResult("shell denied")
	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(r, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Content) != 1 || parsed.Content[0].Type != "text" {
		t.Fatalf("bad content block: %+v", parsed)
	}
	if !strings.Contains(parsed.Content[0].Text, "shell denied") || !parsed.IsError {
		t.Fatalf("bad blocked result: %+v", parsed)
	}
}
