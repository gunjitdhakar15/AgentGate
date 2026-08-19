// Mock MCP tool server used for demos and smoke tests. Reads JSON-RPC over
// stdio, answers initialize / tools/list, and echoes every tools/call back
// with its arguments so you can watch what AgentGate lets through.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/gunjitdhakar15/AgentGate/internal/mcp"
)

func main() {
	s := mcp.NewStream(os.Stdin, os.Stdout)
	for {
		data, err := s.Read()
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		var probe struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(data, &probe); err != nil {
			continue
		}
		switch probe.Method {
		case "initialize":
			_ = s.Write(mcp.Response{JSONRPC: "2.0", ID: probe.ID, Result: json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":{"tools":{}}}`)})
		case "tools/list":
			_ = s.Write(mcp.Response{JSONRPC: "2.0", ID: probe.ID, Result: json.RawMessage(`{"tools":[{"name":"shell","description":"run a shell command"},{"name":"read_file","description":"read a file"}]}`)})
		case "tools/call":
			var call struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(probe.Params, &call)
			argsJSON, _ := json.Marshal(call.Arguments)
			text := fmt.Sprintf("mock executed %s with %s", call.Name, argsJSON)
			out, _ := json.Marshal(map[string]any{
				"content": []map[string]any{{"type": "text", "text": text}},
			})
			_ = s.Write(mcp.Response{JSONRPC: "2.0", ID: probe.ID, Result: out})
		default:
			_ = s.Write(mcp.Response{JSONRPC: "2.0", ID: probe.ID, Result: json.RawMessage(`{}`)})
		}
	}
}
