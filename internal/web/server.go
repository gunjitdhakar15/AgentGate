package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

//go:embed assets/dashboard.html
var assets embed.FS

// Handler builds the dashboard HTTP routes: the page, a stats endpoint, and
// the SSE event stream.
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handlePage)
	mux.HandleFunc("/api/stats", d.handleStats)
	mux.HandleFunc("/events", d.handleSSE)
	return mux
}

func (d *Dashboard) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile("assets/dashboard.html")
	if err != nil {
		http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (d *Dashboard) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(d.Snapshot())
}

func (d *Dashboard) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	writeEvent := func(eType string, payload []byte) {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eType, payload)
		flusher.Flush()
	}

	initial, _ := json.Marshal(event{Type: "snapshot", Data: d.snapshotObject()})
	writeEvent("snapshot", initial)

	ch, done := d.Subscribe()
	defer done()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()

	for {
		select {
		case ev := <-ch:
			b, _ := json.Marshal(ev)
			writeEvent(ev.Type, b)
		case <-tick.C:
			snap, _ := json.Marshal(event{Type: "snapshot", Data: d.snapshotObject()})
			writeEvent("snapshot", snap)
		case <-r.Context().Done():
			return
		}
	}
}
