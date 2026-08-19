package web

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/gunjitdhakar15/AgentGate/internal/audit"
)

// TailFile watches an audit JSONL log and feeds new entries into the
// dashboard. It replays existing content on the first pass, then only new
// lines (handles truncation/rotation). Call the returned cancel func to stop.
func (d *Dashboard) TailFile(ctx context.Context, path string) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var offset int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				offset = d.tailOnce(path, offset)
			}
		}
	}()
}

func (d *Dashboard) tailOnce(path string, offset int64) int64 {
	f, err := os.Open(path)
	if err != nil {
		return offset
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return offset
	}
	if st.Size() < offset {
		return 0 // truncated or rotated
	}
	if st.Size() == offset {
		return offset
	}
	buf := make([]byte, st.Size()-offset)
	if _, err := f.ReadAt(buf, offset); err != nil {
		return offset
	}
	offset = st.Size()
	for _, line := range bytes.Split(buf, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e audit.Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		d.handleEntry(e)
	}
	return offset
}
