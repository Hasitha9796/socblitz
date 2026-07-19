package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Decoding turns a raw log line into an Event with structured fields. Stage 1 is
// a generic syslog (RFC3164) parse for timestamp/host/program/message; stage 2
// runs the decoders.
//
// Decoders use the Wazuh 5.0 engine decoder asset shape, restructured for
// SocBlitz (regex extraction instead of HLP/logpar):
//
//   name: decoder/sshd/0
//   metadata: { module, title, description, compatibility, author, references }
//   parents:  [decoder/syslog/0]        # optional — only run if a parent matched
//   check:    { program: sshd }         # field == value, or field: /regex/
//   parse|message:                      # ordered regex; first match wins
//     - 'Failed password for (?P<dstuser>\S+) from (?P<srcip>...)'
//   normalize:                          # set/derive fields after parsing
//     - map: { event.category: authentication }
//     - check: { dstuser: root }
//       map:   { event.severity: high }

var syslogPRI = regexp.MustCompile(`^<\d{1,3}>`)

var syslogRE = regexp.MustCompile(
	`^(?P<ts>[A-Z][a-z]{2}\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+(?P<prog>[^:\[\s]+)(?:\[\d+\])?:\s*(?P<msg>.*)$`)

// NormalizeOp is one entry in a decoder's `normalize` list.
type NormalizeOp struct {
	Check   map[string]string
	Map     map[string]string
	checkRE map[string]*regexp.Regexp
}

// Decoder is one Wazuh-5.0-shaped decoder asset.
type Decoder struct {
	Name      string
	Metadata  map[string]any
	Parents   []string
	Check     map[string]string   // field -> "value" (equals) | "/regex/"
	Parse     map[string][]string // field -> ordered regex patterns
	Normalize []NormalizeOp

	checkRE map[string]*regexp.Regexp
	parseRE map[string][]*regexp.Regexp
}

func isRegexSpec(s string) bool {
	return len(s) >= 2 && strings.HasPrefix(s, "/") && strings.HasSuffix(s, "/")
}

func (d *Decoder) compile() error {
	d.checkRE = map[string]*regexp.Regexp{}
	for field, spec := range d.Check {
		if isRegexSpec(spec) {
			re, err := regexp.Compile(spec[1 : len(spec)-1])
			if err != nil {
				return fmt.Errorf("%s check[%s]: %w", d.Name, field, err)
			}
			d.checkRE[field] = re
		}
	}
	d.parseRE = map[string][]*regexp.Regexp{}
	for field, pats := range d.Parse {
		for _, p := range pats {
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("%s parse|%s: %w", d.Name, field, err)
			}
			d.parseRE[field] = append(d.parseRE[field], re)
		}
	}
	for i := range d.Normalize {
		op := &d.Normalize[i]
		op.checkRE = map[string]*regexp.Regexp{}
		for field, spec := range op.Check {
			if isRegexSpec(spec) {
				re, err := regexp.Compile(spec[1 : len(spec)-1])
				if err != nil {
					return fmt.Errorf("%s normalize check[%s]: %w", d.Name, field, err)
				}
				op.checkRE[field] = re
			}
		}
	}
	return nil
}

// condPass evaluates a field->spec condition map against the current event.
func condPass(cond map[string]string, condRE map[string]*regexp.Regexp, ev *Event) bool {
	for field, spec := range cond {
		actual := valueOf(ev, field)
		if re, ok := condRE[field]; ok {
			if !re.MatchString(actual) {
				return false
			}
		} else if !strings.EqualFold(actual, spec) {
			return false
		}
	}
	return true
}

func valueOf(ev *Event, field string) string {
	switch field {
	case "program":
		return ev.Program
	case "host":
		return ev.Host
	case "message":
		return ev.Message
	case "raw":
		return ev.Raw
	default:
		return ev.Fields[field]
	}
}

type DecoderSet struct{ decoders []*Decoder }

func (ds *DecoderSet) Count() int { return len(ds.decoders) }

// apply runs the decoders in order against the event, filling ev.Fields, and
// returns the names of the decoders that matched (their `check` passed).
func (ds *DecoderSet) apply(ev *Event) []string {
	matched := map[string]bool{}
	var order []string
	for _, d := range ds.decoders {
		if len(d.Parents) > 0 && !anyMatched(d.Parents, matched) {
			continue
		}
		if !condPass(d.Check, d.checkRE, ev) {
			continue
		}
		// parse|<field>: first pattern that matches contributes its groups
		for field, res := range d.parseRE {
			src := valueOf(ev, field)
			for _, re := range res {
				if m := match(re, src); m != nil {
					for k, v := range m {
						if v != "" {
							ev.Fields[k] = v
						}
					}
					break
				}
			}
		}
		// normalize: conditional static field assignment
		for _, op := range d.Normalize {
			if len(op.Check) > 0 && !condPass(op.Check, op.checkRE, ev) {
				continue
			}
			for k, v := range op.Map {
				ev.Fields[k] = v
			}
		}
		matched[d.Name] = true
		order = append(order, d.Name)
	}
	return order
}

func anyMatched(parents []string, matched map[string]bool) bool {
	for _, p := range parents {
		if matched[p] {
			return true
		}
	}
	return false
}

// ── YAML loading (Wazuh 5.0 asset shape) ──────────────────────────────────────

// ParseDecoderYAML parses one or more decoder assets. Each YAML document may be
// a single decoder mapping (Wazuh style) or a list of them. Multi-document files
// (`---` separated) are supported.
func ParseDecoderYAML(data []byte) ([]*Decoder, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []*Decoder
	for {
		var doc any
		err := dec.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch v := doc.(type) {
		case []any:
			for _, item := range v {
				d, err := decoderFromAny(item)
				if err != nil {
					return nil, err
				}
				out = append(out, d)
			}
		case map[string]any:
			d, err := decoderFromAny(v)
			if err != nil {
				return nil, err
			}
			out = append(out, d)
		case nil:
			// empty document — skip
		default:
			return nil, fmt.Errorf("decoder document must be a mapping or list")
		}
	}
	for _, d := range out {
		if err := d.compile(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func decoderFromAny(item any) (*Decoder, error) {
	m, ok := item.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("decoder must be a mapping")
	}
	d := &Decoder{Check: map[string]string{}, Parse: map[string][]string{}}
	for k, val := range m {
		switch {
		case k == "name":
			d.Name = asString(val)
		case k == "metadata":
			d.Metadata, _ = val.(map[string]any)
		case k == "parents":
			d.Parents = asStringList(val)
		case k == "check":
			d.Check = asCondMap(val)
		case k == "normalize":
			d.Normalize = asNormalize(val)
		case strings.HasPrefix(k, "parse|"):
			d.Parse[strings.TrimPrefix(k, "parse|")] = asStringList(val)
		}
	}
	if d.Name == "" {
		return nil, fmt.Errorf("decoder missing name")
	}
	return d, nil
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func asStringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, asString(e))
		}
		return out
	case nil:
		return nil
	default:
		return []string{asString(t)}
	}
}

// asCondMap accepts either a mapping {field: spec} or a list of single-key maps.
func asCondMap(v any) map[string]string {
	out := map[string]string{}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			out[k] = asString(val)
		}
	case []any:
		for _, item := range t {
			if mm, ok := item.(map[string]any); ok {
				for k, val := range mm {
					out[k] = asString(val)
				}
			}
		}
	}
	return out
}

func asNormalize(v any) []NormalizeOp {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var ops []NormalizeOp
	for _, item := range list {
		mm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		op := NormalizeOp{Check: asCondMap(mm["check"]), Map: asCondMap(mm["map"])}
		ops = append(ops, op)
	}
	return ops
}

// builtinDecoders mirrors engine/decoders/base.yml so the engine works out of
// the box when no decoder YAML is mounted.
func builtinDecoders() *DecoderSet {
	yml := []byte(builtinDecoderYAML)
	list, err := ParseDecoderYAML(yml)
	if err != nil {
		// Should never happen (constant is validated by tests/build); fail loud.
		panic("builtin decoders invalid: " + err.Error())
	}
	return &DecoderSet{decoders: list}
}

// LoadDecoders reads every *.yml/*.yaml in dir. Falls back to built-ins if none.
func LoadDecoders(dir string) (*DecoderSet, error) {
	var files []string
	for _, g := range []string{"*.yml", "*.yaml"} {
		m, _ := filepath.Glob(filepath.Join(dir, g))
		files = append(files, m...)
	}
	var all []*Decoder
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		list, err := ParseDecoderYAML(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		all = append(all, list...)
	}
	if len(all) == 0 {
		return builtinDecoders(), nil
	}
	return &DecoderSet{decoders: all}, nil
}

var activeDecoders = builtinDecoders()

func decode(r RawEvent) Event { return decodeWith(r, activeDecoders) }

func decodeWith(r RawEvent, ds *DecoderSet) Event {
	ev := Event{
		Raw:       r.Message,
		Timestamp: r.Timestamp,
		AgentID:   r.AgentID,
		AgentName: r.AgentName,
		Host:      r.SrcHost,
		Message:   r.Message,
		Fields:    map[string]string{},
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	line := syslogPRI.ReplaceAllString(strings.TrimSpace(r.Message), "")
	ev.Message = line
	if m := match(syslogRE, line); m != nil {
		ev.Program = m["prog"]
		if m["host"] != "" {
			ev.Host = m["host"]
		}
		ev.Message = m["msg"]
	}

	ds.apply(&ev)
	return ev
}

// match runs a regexp and returns a name->value map, or nil if no match.
func match(re *regexp.Regexp, s string) map[string]string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	out := map[string]string{}
	for i, name := range re.SubexpNames() {
		if name != "" {
			out[name] = strings.TrimSpace(m[i])
		}
	}
	return out
}
