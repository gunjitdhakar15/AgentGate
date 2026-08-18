package mcp

import (
	"encoding/json"
	"fmt"
)

// JSON-RPC 2.0 message shapes used by the Model Context Protocol over stdio.

// Request is a client->server method invocation. ID may be a number or string;
// it is kept as json.RawMessage so we can echo it back untouched.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Notification is a one-way message with no response.
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a server->client reply to a Request.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// HasID reports whether the message carries a request id.
func (m *Request) HasID() bool { return len(m.ID) > 0 && string(m.ID) != "null" }

// IDString returns a stable printable id for audit/telemetry.
func (m *Request) IDString() string {
	if !m.HasID() {
		return ""
	}
	var v any
	if err := json.Unmarshal(m.ID, &v); err == nil {
		return fmt.Sprintf("%v", v)
	}
	return string(m.ID)
}

// ParseRequest decodes one inbound JSON payload as a request.
// Notifications and responses are rejected here; callers use ObjectKind first.
func ParseRequest(data []byte) (*Request, error) {
	var m Request
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC request: %w", err)
	}
	if m.JSONRPC != "2.0" {
		return nil, fmt.Errorf("unsupported jsonrpc version %q", m.JSONRPC)
	}
	return &m, nil
}

// ParseNotification decodes one inbound JSON payload as a notification.
func ParseNotification(data []byte) (*Notification, error) {
	var m Notification
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC notification: %w", err)
	}
	return &m, nil
}

// ParseResponse decodes one inbound JSON payload as a response.
func ParseResponse(data []byte) (*Response, error) {
	var m Response
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC response: %w", err)
	}
	return &m, nil
}

// Kind classifies a raw JSON payload before dispatch.
type Kind int

const (
	KindUnknown Kind = iota
	KindRequest
	KindResponse
	KindNotification
)

// ObjectKind inspects the bare minimum of a payload to classify it,
// tolerating malformed extras so the proxy can relabel its audit records.
func ObjectKind(data []byte) Kind {
	var probe struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return KindUnknown
	}
	if probe.JSONRPC != "2.0" {
		return KindUnknown
	}
	switch {
	case len(probe.Method) > 0 && len(probe.ID) == 0:
		return KindNotification
	case len(probe.Method) > 0:
		return KindRequest
	case len(probe.Result) > 0 || len(probe.Error) > 0:
		return KindResponse
	}
	return KindUnknown
}

// BlockedResult builds a well-formed MCP tool call result that reports a
// policy violation while keeping the JSON-RPC exchange green. Tool content
// uses the standard MCP content block shape.
func BlockedResult(reason string) json.RawMessage {
	msg, _ := json.Marshal(map[string]any{
		"content": []map[string]string{
			{"type": "text", "text": "[AgentGate blocked] " + reason},
		},
		"isError": true,
	})
	return msg
}
