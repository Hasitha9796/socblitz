package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// The workbench endpoints power the SocBlitz Engine UI (Extractor / Rule
// Generation / Test tabs). They are read-only and stateless — decode, match,
// and regex-test log lines without persisting anything.

// POST /test — run a raw log line through decode + the active ruleset.
func (s *Server) handleTestLog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
		Program string `json:"program"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	ev := decode(RawEvent{Message: req.Message, Timestamp: time.Now().UTC()})
	if req.Program != "" {
		ev.Program = req.Program
	}
	alerts := s.rules.Eval(&ev)
	writeJSON(w, http.StatusOK, map[string]any{
		"event": map[string]any{
			"program": ev.Program,
			"host":    ev.Host,
			"message": ev.Message,
			"fields":  ev.Fields,
		},
		"alerts":  alerts,
		"matched": len(alerts) > 0,
	})
}

// POST /extractor/test — test YAML-defined decoders (or a single regex pattern,
// legacy) against a sample line, using the same decode path the engine runs in
// production (syslog parse → program-scoped decoders → fields).
func (s *Server) handleExtractorTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		YAML    string `json:"yaml"`
		Pattern string `json:"pattern"` // legacy single-regex mode
		Sample  string `json:"sample"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Legacy: a bare regex tested directly against the sample.
	if strings.TrimSpace(req.YAML) == "" && req.Pattern != "" {
		re, err := regexp.Compile(req.Pattern)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"matched": false, "error": err.Error()})
			return
		}
		fields := match(re, req.Sample)
		writeJSON(w, http.StatusOK, map[string]any{
			"matched": fields != nil, "fields": fields, "groups": re.SubexpNames(),
		})
		return
	}

	// YAML mode: parse Wazuh-5.0-shaped decoder assets and run the real pipeline.
	list, err := ParseDecoderYAML([]byte(req.YAML))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"matched": false, "error": err.Error()})
		return
	}
	set := &DecoderSet{decoders: list}
	ev := decodeWith(RawEvent{Message: req.Sample, Timestamp: time.Now().UTC()}, set)
	matchedNames := set.apply(&ev)
	writeJSON(w, http.StatusOK, map[string]any{
		"matched":  len(matchedNames) > 0,
		"fields":   ev.Fields,
		"decoders": matchedNames,
		"program":  ev.Program,
	})
}

// POST /rules/test — compile a candidate JSON rule and test it against a line.
func (s *Server) handleRuleTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rule    json.RawMessage `json:"rule"`
		Message string          `json:"message"`
		Program string          `json:"program"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	ev := decode(RawEvent{Message: req.Message, Timestamp: time.Now().UTC()})
	if req.Program != "" {
		ev.Program = req.Program
	}
	matched, alert, err := TestRuleJSON(req.Rule, &ev)
	resp := map[string]any{
		"matched": matched,
		"event": map[string]any{
			"program": ev.Program, "message": ev.Message, "fields": ev.Fields,
		},
	}
	if err != nil {
		resp["error"] = err.Error()
	}
	if alert != nil {
		resp["alert"] = alert
	}
	writeJSON(w, http.StatusOK, resp)
}

// GET /rules — list the active ruleset (metadata only).
func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.rules.List())
}

// ── Chronicle-style workbench: UDM normalization + YARA-L ─────────────────────

// POST /normalize — run a raw line through decode + the active CBN parsers and
// return the resulting UDM record (how the engine normalizes the log).
func (s *Server) handleNormalize(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
		Program string `json:"program"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	ev := decode(RawEvent{Message: req.Message, Timestamp: time.Now().UTC()})
	if req.Program != "" {
		ev.Program = req.Program
	}
	udm, matched := s.parsers.Current().Normalize(&ev)
	writeJSON(w, http.StatusOK, map[string]any{
		"event_type": udm.GetString("metadata.event_type"),
		"udm":        udm,
		"fields":     udm.Flat(),
		"parsers":    matched,
		"matched":    len(matched) > 0,
	})
}

// POST /parser/test — test a candidate CBN parser (YAML) against a sample line
// and show the UDM it produces, using the real normalization pipeline.
func (s *Server) handleParserTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		YAML    string `json:"yaml"`
		Sample  string `json:"sample"`
		Program string `json:"program"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	list, err := ParseParserYAML([]byte(req.YAML))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"matched": false, "error": err.Error()})
		return
	}
	set := &ParserSet{parsers: list}
	ev := decode(RawEvent{Message: req.Sample, Timestamp: time.Now().UTC()})
	if req.Program != "" {
		ev.Program = req.Program
	}
	udm, matched := set.Normalize(&ev)
	writeJSON(w, http.StatusOK, map[string]any{
		"matched":    len(matched) > 0,
		"event_type": udm.GetString("metadata.event_type"),
		"udm":        udm,
		"fields":     udm.Flat(),
		"parsers":    matched,
	})
}

// POST /yaral/test — compile a YARA-L rule and evaluate it against one or more
// sample lines. Single-event rules match per line; windowed rules aggregate
// across the supplied lines through a fresh correlator (so brute-force-style
// rules can be exercised by pasting N lines).
func (s *Server) handleYaraLTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rule     string   `json:"rule"`
		Message  string   `json:"message"`
		Messages []string `json:"messages"`
		Program  string   `json:"program"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	rule, err := ParseYaraL(req.Rule)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"matched": false, "error": err.Error()})
		return
	}

	lines := req.Messages
	if len(lines) == 0 && req.Message != "" {
		lines = []string{req.Message}
	}

	set := &YaraLSet{}
	set.add(rule)
	correlator := NewCorrelator(set)

	var alerts []Alert
	events := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		ev := decode(RawEvent{Message: line, Timestamp: time.Now().UTC()})
		if req.Program != "" {
			ev.Program = req.Program
		}
		udm, _ := s.parsers.Current().Normalize(&ev)
		if rule.IsWindowed() {
			alerts = append(alerts, correlator.Observe(udm, &ev)...)
		} else {
			alerts = append(alerts, set.EvalSingle(udm, &ev)...)
		}
		events = append(events, map[string]any{
			"message":    line,
			"event_type": udm.GetString("metadata.event_type"),
			"fields":     udm.Flat(),
		})
	}

	_, threshold := rule.countThreshold()
	summary := map[string]any{
		"name":       rule.Name,
		"level":      rule.Level,
		"windowed":   rule.IsWindowed(),
		"techniques": rule.Techniques,
		"tactics":    rule.Tactics,
		"threshold":  threshold,
	}
	if rule.Match != nil {
		summary["window"] = rule.Match.window.String()
		summary["group_by"] = rule.Match.keys
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"matched": len(alerts) > 0,
		"rule":    summary,
		"events":  events,
		"alerts":  alerts,
	})
}

// GET /yaral/rules — list the active YARA-L ruleset (metadata only).
func (s *Server) handleListYaraL(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.yaral.List())
}
