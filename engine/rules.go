package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Rule is one detection. It is intentionally close to a Sigma rule's shape
// (selection + level + MITRE tags) so a Sigma loader can be added later that
// compiles into this struct. For now rules are authored as JSON.
type Rule struct {
	ID          string            `json:"id"`
	Level       int               `json:"level"`
	Description string            `json:"description"`
	Groups      []string          `json:"groups"`
	Tactics     []string          `json:"mitre_tactics"`
	Techniques  []string          `json:"mitre_techniques"`
	Program     string            `json:"program"` // optional: only events from this program
	Match       string            `json:"match"`   // optional: regex over the message
	Fields      map[string]string `json:"fields"`  // optional: field -> regex the field must match

	matchRE *regexp.Regexp
	fieldRE map[string]*regexp.Regexp
	matchFn func(*Event) bool // set by the Sigma loader; takes precedence
}

func (r *Rule) compile() error {
	if r.Match != "" {
		re, err := regexp.Compile(r.Match)
		if err != nil {
			return fmt.Errorf("rule %s match: %w", r.ID, err)
		}
		r.matchRE = re
	}
	r.fieldRE = map[string]*regexp.Regexp{}
	for k, pat := range r.Fields {
		re, err := regexp.Compile(pat)
		if err != nil {
			return fmt.Errorf("rule %s field %s: %w", r.ID, k, err)
		}
		r.fieldRE[k] = re
	}
	return nil
}

func (r *Rule) matches(ev *Event) bool {
	if r.matchFn != nil {
		return r.matchFn(ev)
	}
	if r.Program != "" && !strings.EqualFold(r.Program, ev.Program) {
		return false
	}
	if r.matchRE != nil && !r.matchRE.MatchString(ev.Message) {
		return false
	}
	for k, re := range r.fieldRE {
		if !re.MatchString(ev.field(k)) {
			return false
		}
	}
	// A rule with no conditions at all never fires (avoids match-everything).
	return r.Program != "" || r.matchRE != nil || len(r.fieldRE) > 0
}

type RuleSet struct{ rules []*Rule }

// LoadRules reads every *.json file in dir as an array of rules.
func LoadRules(dir string) (*RuleSet, error) {
	rs := &RuleSet{}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var batch []*Rule
		if err := json.Unmarshal(data, &batch); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, r := range batch {
			if err := r.compile(); err != nil {
				return nil, err
			}
			rs.rules = append(rs.rules, r)
		}
	}
	return rs, nil
}

// buildAlert renders a matched rule + event into an Alert.
func buildAlert(r *Rule, ev *Event) Alert {
	return Alert{
		AlertID:     newAlertID(),
		Timestamp:   ev.Timestamp,
		RuleID:      r.ID,
		RuleLevel:   r.Level,
		Description: r.Description,
		Groups:      r.Groups,
		Tactics:     r.Tactics,
		Techniques:  r.Techniques,
		AgentID:     ev.AgentID,
		AgentName:   ev.AgentName,
		SrcIP:       ev.field("srcip"),
		DstUser:     ev.field("dstuser"),
		Raw:         ev.Raw,
	}
}

// Eval returns an alert for every rule that matches the event.
func (rs *RuleSet) Eval(ev *Event) []Alert {
	var out []Alert
	for _, r := range rs.rules {
		if r.matches(ev) {
			out = append(out, buildAlert(r, ev))
		}
	}
	return out
}

func (rs *RuleSet) Count() int { return len(rs.rules) }

// RuleMeta is the serialisable summary of a loaded rule (the matcher itself
// isn't serialisable, so we expose metadata only).
type RuleMeta struct {
	ID          string   `json:"id"`
	Level       int      `json:"level"`
	Description string   `json:"description"`
	Groups      []string `json:"groups"`
	Tactics     []string `json:"mitre_tactics"`
	Techniques  []string `json:"mitre_techniques"`
	Format      string   `json:"format"` // "json" | "sigma"
}

func (rs *RuleSet) List() []RuleMeta {
	out := make([]RuleMeta, 0, len(rs.rules))
	for _, r := range rs.rules {
		format := "json"
		if r.matchFn != nil {
			format = "sigma"
		}
		out = append(out, RuleMeta{
			ID: r.ID, Level: r.Level, Description: r.Description,
			Groups: r.Groups, Tactics: r.Tactics, Techniques: r.Techniques, Format: format,
		})
	}
	return out
}

// TestRuleJSON compiles a single JSON rule and evaluates it against a message,
// for the rule-builder workbench (no persistence).
func TestRuleJSON(raw []byte, ev *Event) (matched bool, alert *Alert, err error) {
	var r Rule
	if err = json.Unmarshal(raw, &r); err != nil {
		return false, nil, err
	}
	if err = r.compile(); err != nil {
		return false, nil, err
	}
	if r.matches(ev) {
		a := buildAlert(&r, ev)
		return true, &a, nil
	}
	return false, nil, nil
}
