package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// parser.go — Chronicle CBN-style parsers.
//
// A Chronicle "Config Based Normalizer" parser is an ordered list of filter
// steps that extract raw fields (grok / kv / json) and then map them onto the
// UDM (set). SocBlitz mirrors that shape in YAML:
//
//   name: sshd
//   log_type: SSH
//   check: { program: sshd }          # gate: run only for these events
//   filter:
//     - grok:
//         source: message             # default: message
//         patterns:
//           - 'Failed password for (?:invalid user )?%{USERNAME:user} from %{IP:src_ip}'
//     - set:
//         metadata.event_type: USER_LOGIN
//         metadata.vendor_name: OpenSSH
//         security_result.action: BLOCK
//         principal.ip: '%{src_ip}'
//         target.user.userid: '%{user}'
//     - on: "%{user} == root"         # conditional set
//       set: { security_result.severity: HIGH }
//
// The pipeline runs every parser whose `check` passes and merges their UDM
// output — the normalization stage that feeds YARA-L detection.

type Parser struct {
	Name    string
	LogType string
	Check   map[string]string
	Filters []filterStep
	Source  string // the parser's own YAML document (for view/edit in the UI)

	checkRE map[string]*regexp.Regexp
}

type filterStep struct {
	grok   *grokStep
	kv     *kvStep
	json   *jsonStep
	set    map[string]string // udm path -> template ("%{var}" interpolated)
	rename map[string]string // dst var <- src var
	on     string            // optional condition gating this step's `set`
	onRE   *regexp.Regexp    // compiled regex for "=~ /re/" conditions
	onKind onKind
	onVar  string
	onVal  string
}

type onKind int

const (
	onNone onKind = iota
	onExists
	onEq
	onNeq
	onRe
)

type grokStep struct {
	source   string
	patterns []*regexp.Regexp
	raw      []string
}

type kvStep struct {
	source string
	sep    string // pair separator, default whitespace
	kvSep  string // key/value separator, default "="
}

type jsonStep struct {
	source string
}

func (p *Parser) compile() error {
	p.checkRE = map[string]*regexp.Regexp{}
	for field, spec := range p.Check {
		if isRegexSpec(spec) {
			re, err := regexp.Compile(spec[1 : len(spec)-1])
			if err != nil {
				return fmt.Errorf("%s check[%s]: %w", p.Name, field, err)
			}
			p.checkRE[field] = re
		}
	}
	for i := range p.Filters {
		f := &p.Filters[i]
		if f.grok != nil {
			for _, pat := range f.grok.raw {
				re, err := compileGrok(pat)
				if err != nil {
					return fmt.Errorf("%s grok: %w", p.Name, err)
				}
				f.grok.patterns = append(f.grok.patterns, re)
			}
		}
		if f.on != "" {
			if err := f.compileCond(); err != nil {
				return fmt.Errorf("%s on %q: %w", p.Name, f.on, err)
			}
		}
	}
	return nil
}

var onExpr = regexp.MustCompile(`^%\{([\w.]+)\}\s*(==|!=|=~)?\s*(.*)$`)

func (f *filterStep) compileCond() error {
	m := onExpr.FindStringSubmatch(strings.TrimSpace(f.on))
	if m == nil {
		return fmt.Errorf("cannot parse condition")
	}
	f.onVar = m[1]
	op, rhs := m[2], strings.TrimSpace(m[3])
	rhs = strings.Trim(rhs, `"'`)
	switch op {
	case "":
		f.onKind = onExists
	case "==":
		f.onKind, f.onVal = onEq, rhs
	case "!=":
		f.onKind, f.onVal = onNeq, rhs
	case "=~":
		f.onKind = onRe
		pat := strings.Trim(m[3], " ")
		pat = strings.TrimSuffix(strings.TrimPrefix(pat, "/"), "/")
		re, err := regexp.Compile(pat)
		if err != nil {
			return err
		}
		f.onRE = re
	}
	return nil
}

func (f *filterStep) condPass(vars map[string]string) bool {
	v, ok := vars[f.onVar]
	switch f.onKind {
	case onExists:
		return ok && v != ""
	case onEq:
		return strings.EqualFold(v, f.onVal)
	case onNeq:
		return !strings.EqualFold(v, f.onVal)
	case onRe:
		return f.onRE.MatchString(v)
	}
	return true
}

// ── running a parser ──────────────────────────────────────────────────────────

var interpToken = regexp.MustCompile(`%\{([\w.]+)\}`)

// interpolate replaces %{var} with vars[var]. Returns the result and whether
// every referenced variable resolved to a non-empty value.
func interpolate(tmpl string, vars map[string]string) (string, bool) {
	resolved := true
	out := interpToken.ReplaceAllStringFunc(tmpl, func(tok string) string {
		name := interpToken.FindStringSubmatch(tok)[1]
		v, ok := vars[name]
		if !ok || v == "" {
			resolved = false
			return ""
		}
		return v
	})
	return out, resolved
}

// apply runs the parser's filter steps, mutating vars (extracted fields) and
// writing normalized fields into udm.
func (p *Parser) apply(vars map[string]string, udm UDM) {
	if p.LogType != "" {
		udm.Set("metadata.log_type", p.LogType)
	}
	for i := range p.Filters {
		f := &p.Filters[i]
		switch {
		case f.grok != nil:
			src := vars[orDefault(f.grok.source, "message")]
			for _, re := range f.grok.patterns {
				if got := grokMatch(re, src); got != nil {
					for k, v := range got {
						vars[k] = v
					}
					break
				}
			}
		case f.kv != nil:
			src := vars[orDefault(f.kv.source, "message")]
			for k, v := range parseKV(src, f.kv.sep, f.kvSep(f.kv)) {
				vars[k] = v
			}
		case f.json != nil:
			src := vars[orDefault(f.json.source, "message")]
			flattenJSON(src, vars)
		case len(f.rename) > 0:
			for dst, srcVar := range f.rename {
				if v, ok := vars[srcVar]; ok {
					vars[dst] = v
				}
			}
		case len(f.set) > 0:
			if f.on != "" && !f.condPass(vars) {
				continue
			}
			for path, tmpl := range f.set {
				val, resolved := interpolate(tmpl, vars)
				if resolved && val != "" {
					udm.Set(path, val)
				}
			}
		}
	}
}

func (f *filterStep) kvSep(k *kvStep) string {
	if k.kvSep != "" {
		return k.kvSep
	}
	return "="
}

// parseKV extracts key/value pairs. sep splits pairs (default: whitespace),
// kvSep splits key from value (default "=").
func parseKV(s, sep, kvSep string) map[string]string {
	out := map[string]string{}
	var pairs []string
	if sep == "" {
		pairs = strings.Fields(s)
	} else {
		pairs = strings.Split(s, sep)
	}
	for _, p := range pairs {
		if i := strings.Index(p, kvSep); i > 0 {
			k := strings.TrimSpace(p[:i])
			v := strings.Trim(strings.TrimSpace(p[i+len(kvSep):]), `"`)
			if k != "" && v != "" {
				out[k] = v
			}
		}
	}
	return out
}

// flattenJSON parses a JSON object and writes its leaves into vars as dotted
// keys (nested.field), so `set` templates can reference them.
func flattenJSON(s string, vars map[string]string) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") {
		return
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(s), &obj); err != nil {
		return
	}
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		for k, v := range m {
			key := k
			if prefix != "" {
				key = prefix + "." + k
			}
			if child, ok := v.(map[string]any); ok {
				walk(key, child)
			} else {
				vars[key] = fmt.Sprintf("%v", v)
			}
		}
	}
	walk("", obj)
}

// ── parser set ─────────────────────────────────────────────────────────────────

type ParserSet struct{ parsers []*Parser }

func (ps *ParserSet) Count() int { return len(ps.parsers) }

// Normalize turns a decoded Event into a UDM record. It seeds extraction
// variables from the syslog-parsed Event (and any fields the legacy decoders
// already pulled), runs every parser whose `check` passes, then fills the
// baseline metadata/principal fields every UDM event carries.
func (ps *ParserSet) Normalize(ev *Event) (UDM, []string) {
	vars := map[string]string{
		"message": ev.Message,
		"raw":     ev.Raw,
		"program": ev.Program,
		"host":    ev.Host,
		"loghost": ev.Host,
	}
	for k, v := range ev.Fields { // bridge: legacy decoder output is available too
		vars[k] = v
	}

	udm := UDM{}
	udm.Set("metadata.event_timestamp", ev.Timestamp.UTC().Format(time.RFC3339))
	udm.Set("metadata.product_log_id", ev.Program)

	var matched []string
	for _, p := range ps.parsers {
		if !parserCheckPass(p, ev, vars) {
			continue
		}
		p.apply(vars, udm)
		matched = append(matched, p.Name)
	}

	// Baseline fields present on every normalized event.
	if ev.Host != "" && !udm.Has("principal.hostname") {
		udm.Set("principal.hostname", ev.Host)
	}
	if ev.AgentName != "" {
		udm.Set("observer.hostname", ev.AgentName)
	}
	if ev.AgentID != "" {
		udm.Set("observer.asset_id", ev.AgentID)
	}
	if !udm.Has("metadata.event_type") {
		udm.Set("metadata.event_type", EventGenericEvent)
	}
	udm.Set("metadata.description", ev.Message)
	return udm, matched
}

func parserCheckPass(p *Parser, ev *Event, vars map[string]string) bool {
	for field, spec := range p.Check {
		actual := vars[field]
		if field == "program" {
			actual = ev.Program
		}
		if re, ok := p.checkRE[field]; ok {
			if !re.MatchString(actual) {
				return false
			}
		} else if !strings.EqualFold(actual, spec) {
			return false
		}
	}
	return true
}

// ── YAML loading ────────────────────────────────────────────────────────────

func ParseParserYAML(data []byte) ([]*Parser, error) {
	var out []*Parser
	for _, doc := range splitYAMLDocs(string(data)) {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var v any
		if err := yaml.Unmarshal([]byte(doc), &v); err != nil {
			return nil, err
		}
		if v == nil {
			continue
		}
		p, err := parserFromAny(v)
		if err != nil {
			return nil, err
		}
		p.Source = strings.TrimSpace(doc)
		out = append(out, p)
	}
	for _, p := range out {
		if err := p.compile(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// splitYAMLDocs splits a multi-document YAML stream on lines that are exactly
// "---", preserving each document's text (so parsers keep their editable source).
func splitYAMLDocs(s string) []string {
	var docs []string
	var cur strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "---" {
			docs = append(docs, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteString(line)
		cur.WriteString("\n")
	}
	docs = append(docs, cur.String())
	return docs
}

func parserFromAny(item any) (*Parser, error) {
	m, ok := item.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("parser must be a mapping")
	}
	p := &Parser{Check: map[string]string{}}
	p.Name = asString(m["name"])
	p.LogType = asString(m["log_type"])
	p.Check = asCondMap(m["check"])
	if raw, ok := m["filter"].([]any); ok {
		for _, s := range raw {
			step, err := filterFromAny(s)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p.Name, err)
			}
			p.Filters = append(p.Filters, step)
		}
	}
	if p.Name == "" {
		return nil, fmt.Errorf("parser missing name")
	}
	return p, nil
}

func filterFromAny(s any) (filterStep, error) {
	m, ok := s.(map[string]any)
	if !ok {
		return filterStep{}, fmt.Errorf("filter step must be a mapping")
	}
	var f filterStep
	if g, ok := m["grok"]; ok {
		gm, _ := g.(map[string]any)
		gs := &grokStep{source: asString(gm["source"])}
		if pats, ok := gm["patterns"]; ok {
			gs.raw = asStringList(pats)
		} else if p := asString(gm["pattern"]); p != "" {
			gs.raw = []string{p}
		}
		f.grok = gs
	}
	if k, ok := m["kv"]; ok {
		km, _ := k.(map[string]any)
		f.kv = &kvStep{source: asString(km["source"]), sep: asString(km["sep"]), kvSep: asString(km["kv_sep"])}
	}
	if j, ok := m["json"]; ok {
		jm, _ := j.(map[string]any)
		f.json = &jsonStep{source: asString(jm["source"])}
	}
	if r, ok := m["rename"]; ok {
		f.rename = asCondMap(r)
	}
	if o, ok := m["on"]; ok {
		f.on = asString(o)
	}
	if set, ok := m["set"]; ok {
		f.set = asCondMap(set)
	}
	return f, nil
}

// LoadParsers reads every *.yml/*.yaml in dir; falls back to built-ins if none.
func LoadParsers(dir string) (*ParserSet, error) {
	var files []string
	for _, g := range []string{"*.yml", "*.yaml"} {
		mm, _ := filepath.Glob(filepath.Join(dir, g))
		files = append(files, mm...)
	}
	var all []*Parser
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		list, err := ParseParserYAML(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		all = append(all, list...)
	}
	if len(all) == 0 {
		return builtinParsers(), nil
	}
	return &ParserSet{parsers: all}, nil
}

func builtinParsers() *ParserSet {
	list, err := ParseParserYAML([]byte(builtinParserYAML))
	if err != nil {
		panic("builtin parsers invalid: " + err.Error())
	}
	return &ParserSet{parsers: list}
}

var activeParsers = builtinParsers()
