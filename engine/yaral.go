package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// yaral.go — a YARA-L 2.0 subset.
//
// YARA-L is Chronicle's detection language. A rule declares event variables and
// the UDM predicates they must satisfy, an optional match window that groups
// events by a join key, and a condition over event counts:
//
//   rule ssh_brute_force {
//     meta:
//       author = "socblitz"
//       severity = "HIGH"
//       technique = "T1110"
//     events:
//       $e.metadata.event_type = "USER_LOGIN"
//       $e.security_result.action = "BLOCK"
//       $e.principal.ip = $ip
//     match:
//       $ip over 5m
//     condition:
//       #e >= 5
//   }
//
// Two evaluation modes:
//   • single-event  — no match section; the condition fires on one event
//                     (e.g. `condition: $e`). Evaluated inline, per event.
//   • windowed      — a match section groups events by a join placeholder over a
//                     time window; the condition counts them (`#e >= N`). These
//                     are evaluated by the correlator (see correlator.go).
//
// Supported predicate operators: = != > >= < <= ; a `/regex/` right-hand side
// means regex match; a `$placeholder` right-hand side binds a join key.

type YaraLRule struct {
	Name  string
	Meta  map[string]string
	Preds []yPred  // event predicates (across all event vars)
	Match *yMatch  // nil for single-event rules
	Cond  condNode // reuses the sigma condition AST (selRef=event var, ofNode counts)

	// derived from meta
	Level      int
	Groups     []string
	Tactics    []string
	Techniques []string

	eventVars []string // distinct event variables, in first-seen order
}

// yPred is one `$e.<udm.path> <op> <rhs>` line.
type yPred struct {
	evar        string
	path        string
	op          string // "=", "!=", ">", ">=", "<", "<="
	litRHS      string // literal string / number RHS
	reRHS       *regexp.Regexp
	placeholder string // non-empty when RHS is $x (join-key binding)
}

// yMatch is the `match: $x[, $y] over <duration>` clause.
type yMatch struct {
	keys   []string // placeholder names to group by
	window time.Duration
}

func (r *YaraLRule) IsWindowed() bool { return r.Match != nil }

// countThreshold reports the event variable the condition counts and the
// minimum count that fires it. For a bare "$e" condition the minimum is 1.
func (r *YaraLRule) countThreshold() (string, int) {
	if cn, ok := r.Cond.(countNode); ok {
		return cn.evar, cn.min
	}
	if len(r.eventVars) > 0 {
		return r.eventVars[0], 1
	}
	return "e", 1
}

// ── parsing ─────────────────────────────────────────────────────────────────

var (
	ruleHeaderRE = regexp.MustCompile(`^rule\s+([A-Za-z_]\w*)\s*\{?\s*$`)
	metaLineRE   = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=\s*"?(.*?)"?$`)
	predRE       = regexp.MustCompile(`^\$(\w+)\.([\w.]+)\s*(=~|!=|>=|<=|=|>|<)\s*(.+)$`)
	matchRE      = regexp.MustCompile(`^(.+?)\s+over\s+(\w+)$`)
	durRE        = regexp.MustCompile(`^(\d+)([smhd])$`)
)

// ParseYaraL parses one rule from its text.
func ParseYaraL(text string) (*YaraLRule, error) {
	r := &YaraLRule{Meta: map[string]string{}}
	section := ""
	seenVar := map[string]bool{}
	var condText string

	lines := strings.Split(text, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if m := ruleHeaderRE.FindStringSubmatch(line); m != nil {
			r.Name = m[1]
			continue
		}
		if line == "}" {
			continue
		}
		switch strings.TrimSuffix(line, ":") {
		case "meta":
			section = "meta"
			continue
		case "events":
			section = "events"
			continue
		case "match":
			section = "match"
			continue
		case "condition":
			section = "condition"
			continue
		case "outcome":
			section = "outcome"
			continue
		}

		switch section {
		case "meta":
			if m := metaLineRE.FindStringSubmatch(line); m != nil {
				r.Meta[strings.ToLower(m[1])] = m[2]
			}
		case "events":
			p, err := parsePred(line)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.Name, err)
			}
			if !seenVar[p.evar] {
				seenVar[p.evar] = true
				r.eventVars = append(r.eventVars, p.evar)
			}
			r.Preds = append(r.Preds, p)
		case "match":
			mm, err := parseMatch(line)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.Name, err)
			}
			r.Match = mm
		case "condition":
			condText += " " + line
		case "outcome":
			// parsed but not evaluated in this subset
		}
	}

	if r.Name == "" {
		return nil, fmt.Errorf("rule missing name")
	}
	if len(r.Preds) == 0 {
		return nil, fmt.Errorf("rule %s: no event predicates", r.Name)
	}

	condText = strings.TrimSpace(condText)
	if condText == "" {
		// default: every declared event var must be present.
		condText = strings.Join(r.eventVars, " and ")
	}
	// The condition grammar is the same and/or/not + "N of" AST used by Sigma;
	// there `$e` is a selRef named "e" and `#e >= N` becomes an ofNode.
	ast, err := parseYaraLCondition(condText)
	if err != nil {
		return nil, fmt.Errorf("rule %s condition: %w", r.Name, err)
	}
	r.Cond = ast

	r.applyMeta()
	return r, nil
}

func parsePred(line string) (yPred, error) {
	m := predRE.FindStringSubmatch(line)
	if m == nil {
		return yPred{}, fmt.Errorf("cannot parse event predicate %q", line)
	}
	p := yPred{evar: m[1], path: m[2], op: m[3]}
	rhs := strings.TrimSpace(m[4])
	switch {
	case strings.HasPrefix(rhs, "$"):
		p.placeholder = strings.TrimPrefix(rhs, "$")
	case strings.HasPrefix(rhs, "/") && strings.HasSuffix(rhs, "/") && len(rhs) >= 2:
		re, err := regexp.Compile(rhs[1 : len(rhs)-1])
		if err != nil {
			return yPred{}, err
		}
		p.reRHS = re
		if p.op == "=" {
			p.op = "=~"
		}
	default:
		p.litRHS = strings.Trim(rhs, `"`)
	}
	return p, nil
}

func parseMatch(line string) (*yMatch, error) {
	m := matchRE.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("cannot parse match %q", line)
	}
	var keys []string
	for _, k := range strings.Split(m[1], ",") {
		k = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(k), "$"))
		if k != "" {
			keys = append(keys, k)
		}
	}
	d, err := parseDuration(m[2])
	if err != nil {
		return nil, err
	}
	return &yMatch{keys: keys, window: d}, nil
}

func parseDuration(s string) (time.Duration, error) {
	m := durRE.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("bad duration %q (use 30s/5m/1h/1d)", s)
	}
	n, _ := strconv.Atoi(m[1])
	switch m[2] {
	case "s":
		return time.Duration(n) * time.Second, nil
	case "m":
		return time.Duration(n) * time.Minute, nil
	case "h":
		return time.Duration(n) * time.Hour, nil
	case "d":
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("bad duration unit")
}

// parseYaraLCondition adapts the condition text to the shared Sigma AST parser.
// YARA-L writes counts as "#e >= 5"; the Sigma AST expresses the equivalent as
// an ofNode, so we translate "#e >= N" / "#e > N" into the "N of e*" form the
// existing parser understands, and a bare "$e" into the selRef "e".
func parseYaraLCondition(s string) (condNode, error) {
	s = strings.ReplaceAll(s, "$", "")
	// #e >= N  → treat as a threshold on event var e; encode as countNode.
	countRe := regexp.MustCompile(`#(\w+)\s*(>=|>|==|=)\s*(\d+)`)
	// Replace count expressions with a unique placeholder token the tokenizer
	// keeps intact, then post-process. Simpler: build AST directly for the
	// common shapes. We support: single "#e OP N", single "e", and and/or of
	// event vars. Fall back to the sigma parser for boolean combos of vars.
	if m := countRe.FindStringSubmatch(s); m != nil && countRe.FindAllString(s, -1) != nil {
		// If the whole condition is a single count expression, build a countNode.
		if strings.TrimSpace(countRe.ReplaceAllString(s, "")) == "" {
			n, _ := strconv.Atoi(m[3])
			min := n
			if m[2] == ">" {
				min = n + 1
			}
			return countNode{evar: m[1], min: min}, nil
		}
	}
	// Boolean combination of bare event vars (and/or/not, parentheses).
	return parseCondition(s)
}

// countNode fires when the event var's count meets the threshold. In
// single-event evaluation the count is 1; in windowed evaluation the correlator
// supplies the real count via the results map (key "#<evar>").
type countNode struct {
	evar string
	min  int
}

func (n countNode) eval(m map[string]bool) bool {
	// selRef-style bool map can't carry counts; single-event path sets
	// m[evar]=true when one event matched, which counts as 1.
	return m[n.evar] && n.min <= 1
}

// evalCount is used by the correlator, which knows the real per-key count.
func (n countNode) evalCount(count int) bool { return count >= n.min }

// ── meta → severity / MITRE ─────────────────────────────────────────────────

func (r *YaraLRule) applyMeta() {
	sev := strings.ToLower(r.Meta["severity"])
	r.Level = sigmaLevelOf(sev)
	if r.Level == 5 { // sigmaLevelOf default; try explicit numeric priority
		if p, err := strconv.Atoi(r.Meta["priority"]); err == nil {
			r.Level = p
		}
	}
	r.Groups = []string{"yara-l"}
	if v := r.Meta["category"]; v != "" {
		r.Groups = append(r.Groups, v)
	}
	for _, key := range []string{"technique", "techniques", "mitre", "mitre_technique"} {
		for _, t := range splitList(r.Meta[key]) {
			if strings.HasPrefix(strings.ToLower(t), "t") {
				r.Techniques = append(r.Techniques, strings.ToUpper(t))
			}
		}
	}
	for _, key := range []string{"tactic", "tactics", "mitre_tactic"} {
		for _, t := range splitList(r.Meta[key]) {
			if name, ok := tacticNames[strings.ToLower(strings.ReplaceAll(t, " ", "_"))]; ok {
				r.Tactics = append(r.Tactics, name)
			} else if t != "" {
				r.Tactics = append(r.Tactics, t)
			}
		}
	}
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ── predicate evaluation ──────────────────────────────────────────────────────

// matchEvent reports whether event var `evar` matches all its literal/regex
// predicates for this UDM record, and returns the join-key bindings captured
// from any `$placeholder` predicates.
func (r *YaraLRule) matchEvent(evar string, u UDM) (bool, map[string]string) {
	binds := map[string]string{}
	for _, p := range r.Preds {
		if p.evar != evar {
			continue
		}
		actual := u.GetString(p.path)
		if p.placeholder != "" {
			if actual == "" {
				return false, nil // join key must be present
			}
			binds[p.placeholder] = actual
			continue
		}
		if !compareValues(actual, p.op, p.litRHS, p.reRHS) {
			return false, nil
		}
	}
	return true, binds
}

func compareValues(actual, op, lit string, re *regexp.Regexp) bool {
	if re != nil {
		return re.MatchString(actual)
	}
	switch op {
	case "=", "==":
		return strings.EqualFold(actual, lit)
	case "!=":
		return !strings.EqualFold(actual, lit)
	case ">", ">=", "<", "<=":
		af, err1 := strconv.ParseFloat(actual, 64)
		lf, err2 := strconv.ParseFloat(lit, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		switch op {
		case ">":
			return af > lf
		case ">=":
			return af >= lf
		case "<":
			return af < lf
		case "<=":
			return af <= lf
		}
	}
	return false
}

// ── rule set ──────────────────────────────────────────────────────────────────

type YaraLSet struct {
	single   []*YaraLRule
	windowed []*YaraLRule
}

func (s *YaraLSet) Count() int { return len(s.single) + len(s.windowed) }

func (s *YaraLSet) add(r *YaraLRule) {
	if r.IsWindowed() {
		s.windowed = append(s.windowed, r)
	} else {
		s.single = append(s.single, r)
	}
}

// EvalSingle runs every single-event rule against one normalized event.
func (s *YaraLSet) EvalSingle(u UDM, ev *Event) []Alert {
	var out []Alert
	for _, r := range s.single {
		results := map[string]bool{}
		ok := true
		for _, evar := range r.eventVars {
			matched, _ := r.matchEvent(evar, u)
			results[evar] = matched
			if !matched {
				ok = false
			}
		}
		_ = ok
		if r.Cond.eval(results) {
			out = append(out, buildYaraLAlert(r, u, ev))
		}
	}
	return out
}

func buildYaraLAlert(r *YaraLRule, u UDM, ev *Event) Alert {
	desc := r.Meta["description"]
	if desc == "" {
		desc = r.Name
	}
	srcIP := u.GetString("principal.ip")
	dstUser := u.GetString("target.user.userid")
	if dstUser == "" {
		dstUser = u.GetString("principal.user.userid")
	}
	return Alert{
		AlertID:     newAlertID(),
		Timestamp:   ev.Timestamp,
		RuleID:      r.Name,
		RuleLevel:   r.Level,
		Description: desc,
		Groups:      r.Groups,
		Tactics:     r.Tactics,
		Techniques:  r.Techniques,
		AgentID:     ev.AgentID,
		AgentName:   ev.AgentName,
		SrcIP:       srcIP,
		DstUser:     dstUser,
		Raw:         ev.Raw,
	}
}

// ── loading ─────────────────────────────────────────────────────────────────

// LoadYaraL reads every *.yaral / *.yl file in dir. A file may hold multiple
// rules; they're split on the top-level `rule <name> {` boundary.
func LoadYaraL(dir string) (*YaraLSet, error) {
	set := &YaraLSet{}
	var files []string
	for _, g := range []string{"*.yaral", "*.yl"} {
		mm, _ := filepath.Glob(filepath.Join(dir, g))
		files = append(files, mm...)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, chunk := range splitRules(string(data)) {
			r, err := ParseYaraL(chunk)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			set.add(r)
		}
	}
	if set.Count() == 0 {
		return builtinYaraL(), nil
	}
	return set, nil
}

// splitRules breaks a multi-rule file into individual `rule … { … }` chunks by
// tracking brace depth.
func splitRules(text string) []string {
	var chunks []string
	var cur strings.Builder
	depth := 0
	started := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !started && strings.HasPrefix(trimmed, "rule ") {
			started = true
		}
		if !started {
			continue
		}
		cur.WriteString(line)
		cur.WriteString("\n")
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if started && depth <= 0 && strings.Contains(line, "}") {
			chunks = append(chunks, cur.String())
			cur.Reset()
			started = false
			depth = 0
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		chunks = append(chunks, cur.String())
	}
	return chunks
}

func builtinYaraL() *YaraLSet {
	set := &YaraLSet{}
	for _, chunk := range splitRules(builtinYaraLRules) {
		r, err := ParseYaraL(chunk)
		if err != nil {
			panic("builtin yara-l invalid: " + err.Error())
		}
		set.add(r)
	}
	return set
}

// RuleMeta list for the workbench / management API.
func (s *YaraLSet) List() []RuleMeta {
	out := []RuleMeta{}
	for _, r := range append(append([]*YaraLRule{}, s.single...), s.windowed...) {
		format := "yara-l"
		if r.IsWindowed() {
			format = "yara-l:windowed"
		}
		out = append(out, RuleMeta{
			ID: r.Name, Level: r.Level, Description: orDefault(r.Meta["description"], r.Name),
			Groups: r.Groups, Tactics: r.Tactics, Techniques: r.Techniques, Format: format,
		})
	}
	return out
}
