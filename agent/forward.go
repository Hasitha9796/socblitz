package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// Forwarder batches log events and ships them to the engine's /ingest endpoint,
// with a bounded in-memory buffer and retry/backoff so brief engine outages
// don't drop data.
type Forwarder struct {
	cfg     Config
	agentID string
	client  *http.Client
	in      chan LogEvent
}

func NewForwarder(cfg Config, agentID string) *Forwarder {
	return &Forwarder{
		cfg:     cfg,
		agentID: agentID,
		client:  &http.Client{Timeout: 20 * time.Second},
		in:      make(chan LogEvent, 16384),
	}
}

// Submit queues a raw log line for forwarding (non-blocking; drops if the buffer
// is full, logging once, to protect the agent from unbounded memory growth).
func (f *Forwarder) Submit(source, message, srcHost string) {
	ev := LogEvent{
		Message: message, Source: source, SrcHost: srcHost,
		AgentID: f.agentID, AgentName: f.cfg.Name, Timestamp: time.Now().UTC(),
	}
	select {
	case f.in <- ev:
	default:
		log.Printf("forward buffer full; dropping event from %s", source)
	}
}

func (f *Forwarder) Run(ctx context.Context) {
	const maxBatch = 500
	batch := make([]LogEvent, 0, maxBatch)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := f.postJSON(ctx, "/ingest", batch); err != nil {
			log.Printf("ingest post failed (%d events): %v", len(batch), err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev := <-f.in:
			batch = append(batch, ev)
			if len(batch) >= maxBatch {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func (f *Forwarder) PostFIM(ctx context.Context, events []FimEvent) error {
	return f.postJSON(ctx, "/fim", events)
}

func (f *Forwarder) PostInventory(ctx context.Context, payload InventoryPayload) error {
	return f.postJSON(ctx, "/inventory", payload)
}

// postJSON posts v to the engine path, retrying a few times with backoff.
func (f *Forwarder) postJSON(ctx context.Context, path string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var lastErr error
	backoff := 500 * time.Millisecond
	for attempt := 0; attempt < 4; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, f.cfg.EngineURL+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if f.cfg.EnrollKey != "" {
			req.Header.Set("X-Enroll-Key", f.cfg.EnrollKey)
		}
		resp, err := f.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return nil
			}
			lastErr = &httpError{resp.StatusCode}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return lastErr
}

type httpError struct{ code int }

func (e *httpError) Error() string { return "engine returned status " + itoa(e.code) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
