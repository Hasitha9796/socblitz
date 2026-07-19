package main

import "time"

// RawEvent is what an agent (or a syslog source) forwards to the engine: an
// unparsed log line plus the metadata the forwarder knows about it.
type RawEvent struct {
	Message   string    `json:"message"`
	Source    string    `json:"source"`     // e.g. "journald", "file:/var/log/auth.log", "syslog"
	AgentID   string    `json:"agent_id"`   // set by the engine from the agent's token if empty
	AgentName string    `json:"agent_name"`
	SrcHost   string    `json:"src_host"`   // originating host (for relayed network-device logs)
	Timestamp time.Time `json:"timestamp"`  // optional; engine fills now() if zero
}

// Event is a RawEvent after decoding: structured fields the rule engine matches on.
type Event struct {
	Raw       string
	Timestamp time.Time
	AgentID   string
	AgentName string
	Program   string            // syslog tag / process, e.g. "sshd"
	Host      string
	Message   string            // the human-readable message portion
	Fields    map[string]string // decoded fields: srcip, dstuser, ...
}

func (e *Event) field(k string) string {
	if e.Fields == nil {
		return ""
	}
	return e.Fields[k]
}

// Alert mirrors the ClickHouse wazuh_alerts row the dashboards read.
type Alert struct {
	AlertID     string
	Timestamp   time.Time
	RuleID      string
	RuleLevel   int
	Description string
	Groups      []string
	Tactics     []string
	Techniques  []string
	AgentID     string
	AgentName   string
	SrcIP       string
	DstUser     string
	Raw         string
}
