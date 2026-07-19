package main

import (
	"fmt"
	"sort"
	"strings"
)

// udm.go — the Unified Data Model.
//
// Chronicle (Google SecOps) normalizes every log, regardless of source, into
// one nested schema — the UDM — so detection rules match on stable field paths
// (principal.ip, target.user.userid, metadata.event_type) instead of the raw
// shape of each product's logs. SocBlitz adopts the same idea: CBN-style
// parsers (see parser.go) map raw fields onto a UDM record, and YARA-L rules
// (see yaral.go) match on UDM field paths.
//
// We model the UDM as a nested map[string]any so it serializes straight to the
// JSON shape Chronicle uses and so parsers can set arbitrary nested paths
// without a hand-maintained struct for every one of the hundreds of UDM fields.

// UDM is one normalized event: a tree of nested string-keyed maps and scalars.
type UDM map[string]any

// commonly-used UDM event_type values (a small, representative subset of the
// Chronicle catalog — enough to classify the log sources SocBlitz ships with).
const (
	EventUserLogin      = "USER_LOGIN"
	EventUserUnlock     = "USER_UNLOCK"
	EventProcessLaunch  = "PROCESS_LAUNCH"
	EventNetworkConn    = "NETWORK_CONNECTION"
	EventFileMod        = "FILE_MODIFICATION"
	EventStatusUpdate   = "STATUS_UPDATE"
	EventGenericEvent   = "GENERIC_EVENT"
	EventScanHostVuln   = "SCAN_HOST"
)

// Set assigns a value at a dotted path (e.g. "principal.user.userid"),
// creating intermediate maps as needed. Empty-string values are ignored so a
// parser template that resolves to nothing doesn't plant empty keys.
func (u UDM) Set(path string, val any) {
	if s, ok := val.(string); ok && s == "" {
		return
	}
	keys := strings.Split(path, ".")
	m := map[string]any(u)
	for i, k := range keys {
		if i == len(keys)-1 {
			m[k] = val
			return
		}
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
}

// Get returns the value at a dotted path and whether it was present.
func (u UDM) Get(path string) (any, bool) {
	keys := strings.Split(path, ".")
	var cur any = map[string]any(u)
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// GetString returns the value at a dotted path as a string ("" if absent).
func (u UDM) GetString(path string) string {
	v, ok := u.Get(path)
	if !ok {
		return ""
	}
	return toStr(v)
}

// Has reports whether a (non-empty) value exists at the path.
func (u UDM) Has(path string) bool {
	v, ok := u.Get(path)
	return ok && toStr(v) != ""
}

// Paths returns every leaf path in the record, sorted — used by the workbench
// to render the normalized event as a flat "field = value" table.
func (u UDM) Paths() []string {
	var out []string
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		for k, v := range m {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			if child, ok := v.(map[string]any); ok {
				walk(p, child)
			} else {
				out = append(out, p)
			}
		}
	}
	walk("", u)
	sort.Strings(out)
	return out
}

// Flat renders the record as a sorted map of leaf-path -> string value.
func (u UDM) Flat() map[string]string {
	out := map[string]string{}
	for _, p := range u.Paths() {
		out[p] = u.GetString(p)
	}
	return out
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
