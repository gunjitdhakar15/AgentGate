package web

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
)

const maxRecent = 200

type toolStats struct {
	Allowed  int64 `json:"allowed"`
	Blocked  int64 `json:"blocked"`
	Redacted int64 `json:"redacted"`
}

type snapshot struct {
	Started  time.Time             `json:"started"`
	Counters map[string]int64      `json:"counters"`
	Tools    map[string]*toolStats `json:"tools"`
	Recent   []audit.Entry         `json:"recent"`
}

type event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// Dashboard aggregates audit entries into live counters and broadcasts them
// to subscribed browser clients over SSE.
type Dashboard struct {
	mu       sync.RWMutex
	started  time.Time
	total    int64
	allowed  int64
	blocked  int64
	redacted int64
	protocol int64
	tools    map[string]*toolStats
	recent   []audit.Entry
	subs     map[chan event]struct{}
}

// New creates an empty dashboard.
func New() *Dashboard {
	return &Dashboard{
		started: time.Now(),
		tools:   make(map[string]*toolStats),
		recent:  make([]audit.Entry, 0, maxRecent),
		subs:    make(map[chan event]struct{}),
	}
}

// Notify feeds one audit entry into the dashboard.
func (d *Dashboard) Notify(e audit.Entry) {
	d.handleEntry(e)
}

func (d *Dashboard) handleEntry(e audit.Entry) {
	d.mu.Lock()
	switch e.Kind {
	case "request":
		d.total++
	case "response":
		if e.Tool != "" {
			d.allowed++
			d.toolLocked(e.Tool).Allowed++
		}
	case "blocked":
		d.blocked++
		if e.Tool != "" {
			d.toolLocked(e.Tool).Blocked++
		}
	case "redacted":
		d.redacted++
		if e.Tool != "" {
			d.toolLocked(e.Tool).Redacted++
		}
	case "protocol", "error":
		d.protocol++
	}
	d.recent = append(d.recent, e)
	if len(d.recent) > maxRecent {
		d.recent = d.recent[len(d.recent)-maxRecent:]
	}
	ev := event{Type: "entry", Data: e}
	chans := make([]chan event, 0, len(d.subs))
	for ch := range d.subs {
		chans = append(chans, ch)
	}
	d.mu.Unlock()

	for _, ch := range chans {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (d *Dashboard) toolLocked(name string) *toolStats {
	st, ok := d.tools[name]
	if !ok {
		st = &toolStats{}
		d.tools[name] = st
	}
	return st
}

// Subscribe registers a client channel for live events and returns a cancel
// function that unregisters it.
func (d *Dashboard) Subscribe() (<-chan event, func()) {
	ch := make(chan event, 256)
	d.mu.Lock()
	d.subs[ch] = struct{}{}
	d.mu.Unlock()
	return ch, func() {
		d.mu.Lock()
		delete(d.subs, ch)
		close(ch)
		d.mu.Unlock()
	}
}

// Snapshot encodes the current state as JSON for a full client paint.
func (d *Dashboard) Snapshot() []byte {
	b, err := json.Marshal(d.snapshotObject())
	if err != nil {
		return []byte(`{}`)
	}
	return b
}

func (d *Dashboard) snapshotObject() snapshot {
	d.mu.RLock()
	defer d.mu.RUnlock()
	tools := make(map[string]*toolStats, len(d.tools))
	for k, v := range d.tools {
		t := *v
		tools[k] = &t
	}
	recent := make([]audit.Entry, len(d.recent))
	copy(recent, d.recent)
	return snapshot{
		Started: d.started,
		Counters: map[string]int64{
			"total":         d.total,
			"allowed":       d.allowed,
			"blocked":       d.blocked,
			"redacted":      d.redacted,
			"protocolError": d.protocol,
		},
		Tools:  tools,
		Recent: recent,
	}
}
