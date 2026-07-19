package main

import "time"

// LogEvent is the wire shape the engine's /ingest expects (matches engine.RawEvent).
type LogEvent struct {
	Message   string    `json:"message"`
	Source    string    `json:"source"`
	AgentID   string    `json:"agent_id"`
	AgentName string    `json:"agent_name"`
	SrcHost   string    `json:"src_host,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// FimEvent matches the engine's /fim shape.
type FimEvent struct {
	Path      string    `json:"path"`
	Action    string    `json:"action"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	AgentID   string    `json:"agent_id"`
	AgentName string    `json:"agent_name"`
	Timestamp time.Time `json:"timestamp"`
}

// InvPackage / InventoryPayload match the engine's /inventory shape.
type InvPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InventoryPayload struct {
	AgentID   string       `json:"agent_id"`
	AgentName string       `json:"agent_name"`
	Packages  []InvPackage `json:"packages"`
}
