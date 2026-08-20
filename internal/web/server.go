package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

//go:embed assets
var assets embed.FS

// Handler builds the dashboard HTTP routes: the landing page, the live
// dashboard, a stats endpoint, and the SSE event stream.
func (d *Dashboard) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleLanding)
	mux.HandleFunc("/dashboard", d.handleDashboard)
	mux.HandleFunc("/api/stats", d.handleStats)
	mux.HandleFunc("/events", d.handleSSE)
	return mux
}

func (d *Dashboard) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	d.serveAsset(w, "assets/landing.html", "text/html; charset=utf-8")
}

func (d *Dashboard) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dashboard" {
		http.NotFound(w, r)
		return
	}
	d.serveAsset(w, "assets/dashboard.html", "text/html; charset=utf-8")
}

func (d *Dashboard) serveAsset(w http.ResponseWriter, name, contentType string) {
	data, err := assets.ReadFile(name)
	if err != nil {
		http.Error(w, "asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
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
