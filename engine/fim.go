package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// File Integrity Monitoring: the agent reports file create/modify/delete with a
// hash; the engine turns each into an alert row (no rule needed). Levels follow
// Wazuh's syscheck convention (added/deleted are noisier than modified).

type FimEvent struct {
	Path      string    `json:"path"`
	Action    string    `json:"action"` // created | modified | deleted
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	AgentID   string    `json:"agent_id"`
	AgentName string    `json:"agent_name"`
	Timestamp time.Time `json:"timestamp"`
}

var fimRule = map[string]struct {
	id    string
	level int
	verb  string
}{
	"created":  {"554", 5, "added to the system"},
	"modified": {"550", 7, "modified"},
	"deleted":  {"553", 7, "deleted"},
}

func (s *Server) handleFIM(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var events []FimEvent
	if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	alerts := make([]Alert, 0, len(events))
	for _, e := range events {
		meta := fimRule[e.Action]
		if meta.id == "" {
			meta = fimRule["modified"]
		}
		ts := e.Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		raw, _ := json.Marshal(map[string]any{
			"syscheck": map[string]any{"path": e.Path, "sha256_after": e.SHA256, "size_after": e.Size, "event": e.Action},
			"agent":    map[string]any{"id": e.AgentID, "name": e.AgentName},
			"timestamp": ts.Format(time.RFC3339),
		})
		alerts = append(alerts, Alert{
			AlertID: newAlertID(), Timestamp: ts, RuleID: meta.id, RuleLevel: meta.level,
			Description: fmt.Sprintf("File %s: %s", meta.verb, e.Path),
			Groups:      []string{"ossec", "syscheck", "fim"},
			Tactics:     []string{"Persistence"}, Techniques: []string{"T1565"},
			AgentID: e.AgentID, AgentName: e.AgentName, Raw: string(raw),
		})
		s.touchFromEvent(e.AgentID)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.ch.InsertAlerts(ctx, alerts); err != nil {
		http.Error(w, "insert failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]int{"alerts": len(alerts)})
}
