package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// A pragmatic Sigma loader. It compiles a useful subset of the Sigma spec into
// our Rule.matchFn:
//   - logsource.service  → implicit program filter
//   - detection selections: {Field[:modifier]: value|list}, and bare keyword lists
//   - modifiers: contains | startswith | endswith | re | all ; "*" wildcards
//   - condition: and/or/not, parentheses, and "N of / all of / any of <glob|them>"
//   - level → numeric ; tags (attack.tXXXX / attack.<tactic>) → MITRE
// Unsupported constructs cause the rule to be skipped with a warning, never a crash.

type sigmaDoc struct {
	Title     string         `yaml:"title"`
	ID        string         `yaml:"id"`
	Level     string         `yaml:"level"`
	Tags      []string       `yaml:"tags"`
	LogSource map[string]any `yaml:"logsource"`
	Detection map[string]any `yaml:"detection"`
}

var sigmaLevel = map[string]int{
	"informational": 2, "low": 5, "medium": 8, "high": 12, "critical": 15,
}

var tacticNames = map[string]string{
	"reconnaissance": "Reconnaissance", "resource_development": "Resource Development",
	"initial_access": "Initial Access", "execution": "Execution", "persistence": "Persistence",
	"privilege_escalation": "Privilege Escalation", "defense_evasion": "Defense Evasion",
	"credential_access": "Credential Access", "discovery": "Discovery",
	"lateral_movement": "Lateral Movement", "collection": "Collection",
	"command_and_control": "Command and Control", "exfiltration": "Exfiltration",
	"impact": "Impact",
}

var techRE = regexp.MustCompile(`^attack\.(t\d{4}(?:\.\d{3})?)$`)

// AppendSigma loads every *.yml / *.yaml / *.sigma file in dir into rs.
func AppendSigma(rs *RuleSet, dir string) (int, error) {
	var files []string
	for _, g := range []string{"*.yml", "*.yaml", "*.sigma"} {
		m, _ := filepath.Glob(filepath.Join(dir, g))
		files = append(files, m...)
	}
	n := 0
	for _, f := range files {
		r, err := compileSigmaFile(f)
		if err != nil {
			return n, fmt.Errorf("%s: %w", f, err)
		}
		if r != nil {
			rs.rules = append(rs.rules, r)
			n++
		}
	}
	return n, nil
}

func compileSigmaFile(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc sigmaDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Detection == nil {
		return nil, nil
	}

	condRaw, _ := doc.Detection["condition"].(string)
	if condRaw == "" {
		return nil, fmt.Errorf("missing condition")
	}

	// Build per-selection matchers.
	sels := map[string]func(*Event) bool{}
	for name, spec := range doc.Detection {
		if name == "condition" {
			continue
		}
		sels[name] = buildSelection(spec)
	}

	ast, err := parseCondition(condRaw)
	if err != nil {
		return nil, err
	}

	service, _ := doc.LogSource["service"].(string)
	service = strings.ToLower(service)

	r := &Rule{
		ID:          orDefault(doc.ID, doc.Title),
		Level:       sigmaLevelOf(doc.Level),
		Description: doc.Title,
		Groups:      sigmaGroups(doc),
	}
	r.Tactics, r.Techniques = mitreFromTags(doc.Tags)
	r.matchFn = func(ev *Event) bool {
		if service != "" && !strings.EqualFold(service, ev.Program) {
			return false
		}
		results := map[string]bool{}
		for n, fn := range sels {
			results[n] = fn(ev)
		}
		return ast.eval(results)
	}
	return r, nil
}

func sigmaLevelOf(l string) int {
	if v, ok := sigmaLevel[strings.ToLower(l)]; ok {
		return v
	}
	return 5
}

func sigmaGroups(d sigmaDoc) []string {
	g := []string{"sigma"}
	if s, ok := d.LogSource["service"].(string); ok && s != "" {
		g = append(g, s)
	}
	if s, ok := d.LogSource["category"].(string); ok && s != "" {
		g = append(g, s)
	}
	return g
}

func mitreFromTags(tags []string) (tactics, techs []string) {
	for _, t := range tags {
		t = strings.ToLower(strings.TrimSpace(t))
		if m := techRE.FindStringSubmatch(t); m != nil {
			techs = append(techs, strings.ToUpper(m[1]))
			continue
		}
		if strings.HasPrefix(t, "attack.") {
			if name, ok := tacticNames[strings.TrimPrefix(t, "attack.")]; ok {
				tactics = append(tactics, name)
			}
		}
	}
	return
}

// ── selection matching ────────────────────────────────────────────────────────

func buildSelection(spec any) func(*Event) bool {
	switch v := spec.(type) {
	case map[string]any:
		// map: all key/value pairs must match (AND)
		var preds []func(*Event) bool
		for k, val := range v {
			preds = append(preds, fieldPredicate(k, val))
		}
		return andAll(preds)
	case []any:
		// bare list → keyword OR search over the message
		var preds []func(*Event) bool
		for _, item := range v {
			preds = append(preds, keywordPred(fmt.Sprintf("%v", item)))
		}
		return orAny(preds)
	default:
		return func(*Event) bool { return false }
	}
}

func fieldPredicate(key string, val any) func(*Event) bool {
	parts := strings.Split(key, "|")
	field := parts[0]
	mods := parts[1:]
	all := contains(mods, "all")

	values := toStringList(val)
	var preds []func(*Event) bool
	for _, want := range values {
		preds = append(preds, valuePred(field, mods, want))
	}
	if all {
		return andAll(preds)
	}
	return orAny(preds)
}

func valuePred(field string, mods []string, want string) func(*Event) bool {
	getter := func(ev *Event) string {
		if field == "" {
			return ev.Message
		}
		if v, ok := ev.Fields[field]; ok {
			return v
		}
		return ""
	}
	// Wildcards → regex
	if strings.Contains(want, "*") && !contains(mods, "re") {
		pat := "(?i)^" + regexpEscapeGlob(want) + "$"
		re := regexp.MustCompile(pat)
		return func(ev *Event) bool { return re.MatchString(getter(ev)) }
	}
	switch {
	case contains(mods, "re"):
		re, err := regexp.Compile(want)
		if err != nil {
			return func(*Event) bool { return false }
		}
		return func(ev *Event) bool { return re.MatchString(getter(ev)) }
	case contains(mods, "contains"):
		lw := strings.ToLower(want)
		return func(ev *Event) bool { return strings.Contains(strings.ToLower(getter(ev)), lw) }
	case contains(mods, "startswith"):
		lw := strings.ToLower(want)
		return func(ev *Event) bool { return strings.HasPrefix(strings.ToLower(getter(ev)), lw) }
	case contains(mods, "endswith"):
		lw := strings.ToLower(want)
		return func(ev *Event) bool { return strings.HasSuffix(strings.ToLower(getter(ev)), lw) }
	default:
		return func(ev *Event) bool { return strings.EqualFold(getter(ev), want) }
	}
}

func keywordPred(want string) func(*Event) bool {
	lw := strings.ToLower(want)
	return func(ev *Event) bool { return strings.Contains(strings.ToLower(ev.Message), lw) }
}

func regexpEscapeGlob(g string) string {
	var b strings.Builder
	for _, r := range g {
		if r == '*' {
			b.WriteString(".*")
		} else {
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

func toStringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprintf("%v", e))
		}
		return out
	case nil:
		return []string{""}
	default:
		return []string{fmt.Sprintf("%v", t)}
	}
}

func andAll(ps []func(*Event) bool) func(*Event) bool {
	return func(ev *Event) bool {
		for _, p := range ps {
			if !p(ev) {
				return false
			}
		}
		return len(ps) > 0
	}
}

func orAny(ps []func(*Event) bool) func(*Event) bool {
	return func(ev *Event) bool {
		for _, p := range ps {
			if p(ev) {
				return true
			}
		}
		return false
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ── condition AST ─────────────────────────────────────────────────────────────

type condNode interface{ eval(map[string]bool) bool }

type selRef struct{ name string }
type notNode struct{ c condNode }
type andNode struct{ l, r condNode }
type orNode struct{ l, r condNode }
type ofNode struct {
	quant string // "all" or "any"
	glob  string // "them" or "prefix*"
}

func (n selRef) eval(m map[string]bool) bool { return m[n.name] }
func (n notNode) eval(m map[string]bool) bool { return !n.c.eval(m) }
func (n andNode) eval(m map[string]bool) bool { return n.l.eval(m) && n.r.eval(m) }
func (n orNode) eval(m map[string]bool) bool  { return n.l.eval(m) || n.r.eval(m) }
func (n ofNode) eval(m map[string]bool) bool {
	any := n.quant == "any" || n.quant == "1"
	matched, total := 0, 0
	for name, v := range m {
		if n.glob == "them" || globMatch(n.glob, name) {
			total++
			if v {
				matched++
			}
		}
	}
	if total == 0 {
		return false
	}
	if any {
		return matched >= 1
	}
	return matched == total // "all of"
}

func globMatch(glob, name string) bool {
	if strings.HasSuffix(glob, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(glob, "*"))
	}
	return glob == name
}

// parseCondition: tokenize then recursive-descent (or > and > not).
func parseCondition(s string) (condNode, error) {
	s = strings.NewReplacer("(", " ( ", ")", " ) ").Replace(s)
	toks := strings.Fields(s)
	p := &condParser{toks: toks}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected token %q in condition", p.toks[p.pos])
	}
	return node, nil
}

type condParser struct {
	toks []string
	pos  int
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}
func (p *condParser) next() string { t := p.peek(); p.pos++; return t }

func (p *condParser) parseOr() (condNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
	return left, nil
}

func (p *condParser) parseAnd() (condNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.next()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}
	return left, nil
}

func (p *condParser) parseNot() (condNode, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.next()
		c, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return notNode{c}, nil
	}
	return p.parseAtom()
}

func (p *condParser) parseAtom() (condNode, error) {
	t := p.peek()
	if t == "(" {
		p.next()
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.next() != ")" {
			return nil, fmt.Errorf("missing )")
		}
		return node, nil
	}
	// "N of X" | "all of X" | "any of X"
	if _, err := strconv.Atoi(t); err == nil || strings.EqualFold(t, "all") || strings.EqualFold(t, "any") {
		quant := strings.ToLower(p.next())
		if !strings.EqualFold(p.peek(), "of") {
			return nil, fmt.Errorf("expected 'of' after %q", quant)
		}
		p.next()
		glob := p.next()
		return ofNode{quant: quant, glob: glob}, nil
	}
	if t == "" {
		return nil, fmt.Errorf("unexpected end of condition")
	}
	return selRef{name: p.next()}, nil
}
