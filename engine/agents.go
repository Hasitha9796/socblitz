package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// AgentInfo is the engine's registry record for one enrolled endpoint.
type AgentInfo struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Hostname   string    `json:"hostname"`
	IP         string    `json:"ip"`
	OS         string    `json:"os"`         // linux | windows | macos | unknown
	OSVersion  string    `json:"os_version"`
	Version    string    `json:"version"`
	Group      string    `json:"group"`
	LastSeen   time.Time `json:"last_seen"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// disconnectAfter: agents not seen within this window report as "disconnected".
const disconnectAfter = 15 * time.Minute

func (a AgentInfo) status() string {
	if a.LastSeen.IsZero() {
		return "never_connected"
	}
	if time.Since(a.LastSeen) > disconnectAfter {
		return "disconnected"
	}
	return "active"
}

// managerShape renders an agent in the dict shape the socblitz backend's agent
// sync worker already understands (id/name/ip/os{platform,version}/status/...).
func (a AgentInfo) managerShape() map[string]any {
	return map[string]any{
		"id": a.ID, "name": a.Name, "ip": a.IP,
		"os":      map[string]string{"platform": a.OS, "version": a.OSVersion},
		"status":  a.status(),
		"version": a.Version, "group": a.Group,
		"lastKeepAlive": a.LastSeen.UTC().Format(time.RFC3339),
	}
}

// deriveAgentID makes a stable short id from the hostname (so re-enroll of the
// same host is idempotent). "000" stays reserved for the engine/manager itself.
func deriveAgentID(hostname string) string {
	h := sha256.Sum256([]byte(strings.ToLower(hostname)))
	return hex.EncodeToString(h[:])[:12]
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

type enrollReq struct {
	Hostname  string `json:"hostname"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	OS        string `json:"os"`
	OSVersion string `json:"os_version"`
	Version   string `json:"version"`
	Group     string `json:"group"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req enrollReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Hostname == "" {
		http.Error(w, "hostname required", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	ai := AgentInfo{
		ID: deriveAgentID(req.Hostname), Name: orDefault(req.Name, req.Hostname),
		Hostname: req.Hostname, IP: req.IP, OS: normalizeOS(req.OS), OSVersion: req.OSVersion,
		Version: req.Version, Group: req.Group, LastSeen: now, EnrolledAt: now,
	}
	if err := s.ch.UpsertAgent(r.Context(), ai); err != nil {
		http.Error(w, "enroll failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"agent_id": ai.ID, "name": ai.Name})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := r.URL.Query().Get("agent_id")
	if id != "" {
		s.ch.Touch(r.Context(), id)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.ch.ListAgents(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Return manager-compatible shape so the backend sync worker is unchanged.
	out := make([]map[string]any, 0, len(agents))
	for _, a := range agents {
		out = append(out, a.managerShape())
	}
	writeJSON(w, http.StatusOK, out)
}

func normalizeOS(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "windows"):
		return "windows"
	case strings.Contains(s, "darwin"), strings.Contains(s, "mac"):
		return "macos"
	case strings.Contains(s, "linux"):
		return "linux"
	case s == "":
		return "unknown"
	default:
		return s
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// touchFromEvent keeps last_seen fresh from an agent's log traffic too.
func (s *Server) touchFromEvent(agentID string) {
	if agentID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	go func() { defer cancel(); s.ch.Touch(ctx, agentID) }()
}
