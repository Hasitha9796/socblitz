package main

import (
	"fmt"
	"regexp"
	"strings"
)

// grok.go — a small grok implementation.
//
// Chronicle's CBN parsers extract fields from raw text with grok, the same
// pattern language Logstash uses: %{PATTERN} matches a named regex from a
// library, and %{PATTERN:field} additionally captures the match into `field`.
// Patterns compose (a pattern's definition may reference other patterns), which
// is what makes grok terse — %{SYSLOGBASE} pulls apart a whole syslog header in
// one token. We compile a grok expression into a Go regexp with (?P<field>…)
// named captures.

// grokPatterns is the built-in library. Values may reference other patterns via
// %{NAME}; expansion is recursive with a depth guard.
var grokPatterns = map[string]string{
	"WORD":       `\b\w+\b`,
	"NOTSPACE":   `\S+`,
	"SPACE":      `\s*`,
	"DATA":       `.*?`,
	"GREEDYDATA": `.*`,
	"INT":        `[+-]?\d+`,
	"NUMBER":     `[+-]?\d+(?:\.\d+)?`,
	"BASE10NUM":  `[+-]?\d+(?:\.\d+)?`,
	"POSINT":     `\d+`,
	"PID":        `\d+`,
	"PORT":       `\d{1,5}`,
	"IPV4":       `(?:\d{1,3}\.){3}\d{1,3}`,
	"IP":         `(?:\d{1,3}\.){3}\d{1,3}`,
	"USERNAME":   `[a-zA-Z0-9._@$-]+`,
	"USER":       `[a-zA-Z0-9._@$-]+`,
	"HOSTNAME":   `\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.[0-9A-Za-z][0-9A-Za-z-]{0,62})*\b`,
	"PROG":       `[\w.\/%-]+`,
	"PATH":       `(?:/[\w.\-]+)+`,
	"QUOTEDSTRING": `"[^"]*"`,
	"MAC":        `(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}`,
	"LOGLEVEL":   `(?i:trace|debug|info|notice|warn(?:ing)?|err(?:or)?|crit(?:ical)?|alert|emerg(?:ency)?|fatal)`,
	// syslog RFC3164 header pieces
	"MONTH":            `\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b`,
	"MONTHDAY":         `(?:[0 ]?[1-9]|[12][0-9]|3[01])`,
	"TIME":             `\d{2}:\d{2}:\d{2}`,
	"SYSLOGTIMESTAMP":  `%{MONTH}\s+%{MONTHDAY}\s+%{TIME}`,
	"SYSLOGHOST":       `%{HOSTNAME}`,
	"SYSLOGPROG":       `%{PROG:program}(?:\[%{PID:pid}\])?`,
	"SYSLOGBASE":       `%{SYSLOGTIMESTAMP:timestamp}\s+%{SYSLOGHOST:loghost}\s+%{SYSLOGPROG}:`,
}

var grokToken = regexp.MustCompile(`%\{(\w+)(?::([\w.]+))?\}`)

// compileGrok expands a grok expression into a Go regexp. Named captures use
// (?P<field>…); the field name has dots replaced with "__" because Go regexp
// group names must be alphanumeric (the parser maps them back).
func compileGrok(expr string) (*regexp.Regexp, error) {
	expanded, err := expandGrok(expr, 0)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile(expanded)
	if err != nil {
		return nil, fmt.Errorf("grok %q -> %q: %w", expr, expanded, err)
	}
	return re, nil
}

func expandGrok(expr string, depth int) (string, error) {
	if depth > 20 {
		return "", fmt.Errorf("grok expansion too deep (cyclic pattern?)")
	}
	if !strings.Contains(expr, "%{") {
		return expr, nil
	}
	var errOut error
	out := grokToken.ReplaceAllStringFunc(expr, func(tok string) string {
		m := grokToken.FindStringSubmatch(tok)
		name, field := m[1], m[2]
		def, ok := grokPatterns[name]
		if !ok {
			errOut = fmt.Errorf("unknown grok pattern %%{%s}", name)
			return tok
		}
		sub, err := expandGrok(def, depth+1)
		if err != nil {
			errOut = err
			return tok
		}
		if field != "" {
			return "(?P<" + grokGroupName(field) + ">" + sub + ")"
		}
		return "(?:" + sub + ")"
	})
	return out, errOut
}

// Go regexp group names can't contain '.', so dotted grok field names
// (%{IP:src.ip}) are encoded and decoded around the regexp.
func grokGroupName(field string) string { return strings.ReplaceAll(field, ".", "__") }
func grokFieldName(group string) string { return strings.ReplaceAll(group, "__", ".") }

// grokMatch runs a compiled grok regexp and returns captured fields (decoded
// names), or nil if the expression didn't match.
func grokMatch(re *regexp.Regexp, s string) map[string]string {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	out := map[string]string{}
	for i, name := range re.SubexpNames() {
		if name == "" {
			continue
		}
		if v := strings.TrimSpace(m[i]); v != "" {
			out[grokFieldName(name)] = v
		}
	}
	return out
}
