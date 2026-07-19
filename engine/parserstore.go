package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// parserstore.go — runtime management of CBN parsers.
//
// Two tiers of parsers make up the active set:
//   • base    — built-in + file-loaded parsers (read-only; ship with the image)
//   • custom  — user-defined parsers created/edited through the UI, persisted in
//               ClickHouse (wazuh.engine_parsers) so they survive restarts.
//
// A custom parser with the same name as a base parser overrides it. The store
// rebuilds the active *ParserSet on every change and hands it to the pipeline
// through Current(), so edits take effect immediately with no restart.

type ParserStore struct {
	mu     sync.RWMutex
	base   []*Parser
	custom map[string]*Parser
	active *ParserSet
	ch     *CHClient
}

// ParserInfo is the metadata + source the management API returns.
type ParserInfo struct {
	Name    string `json:"name"`
	LogType string `json:"log_type"`
	Source  string `json:"source"` // "builtin" | "custom"
	YAML    string `json:"yaml"`
}

func NewParserStore(base *ParserSet, ch *CHClient) *ParserStore {
	s := &ParserStore{base: base.parsers, custom: map[string]*Parser{}, ch: ch}
	s.rebuild()
	return s
}

// rebuild recomputes the active set: custom parsers first (overriding base by
// name), then the remaining base parsers. Custom order is name-sorted so the
// merge is deterministic.
func (s *ParserStore) rebuild() {
	names := make([]string, 0, len(s.custom))
	for n := range s.custom {
		names = append(names, n)
	}
	sort.Strings(names)

	overridden := map[string]bool{}
	var list []*Parser
	for _, n := range names {
		list = append(list, s.custom[n])
		overridden[n] = true
	}
	for _, p := range s.base {
		if !overridden[p.Name] {
			list = append(list, p)
		}
	}
	s.active = &ParserSet{parsers: list}
}

// Current returns the live parser set for normalization.
func (s *ParserStore) Current() *ParserSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

func (s *ParserStore) isBuiltin(name string) bool {
	for _, p := range s.base {
		if p.Name == name {
			return true
		}
	}
	return false
}

// List returns every active parser's metadata + editable source.
func (s *ParserStore) List() []ParserInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []ParserInfo{}
	for _, p := range s.active.parsers {
		src := "builtin"
		if _, ok := s.custom[p.Name]; ok {
			src = "custom"
		}
		out = append(out, ParserInfo{Name: p.Name, LogType: p.LogType, Source: src, YAML: p.Source})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns one parser by name.
func (s *ParserStore) Get(name string) (ParserInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.active.parsers {
		if p.Name == name {
			src := "builtin"
			if _, ok := s.custom[p.Name]; ok {
				src = "custom"
			}
			return ParserInfo{Name: p.Name, LogType: p.LogType, Source: src, YAML: p.Source}, true
		}
	}
	return ParserInfo{}, false
}

// Upsert validates a parser YAML (must define exactly one parser), persists it,
// and rebuilds the active set. It returns the saved parser's metadata.
func (s *ParserStore) Upsert(ctx context.Context, yaml string) (ParserInfo, error) {
	list, err := ParseParserYAML([]byte(yaml))
	if err != nil {
		return ParserInfo{}, fmt.Errorf("invalid parser: %w", err)
	}
	if len(list) != 1 {
		return ParserInfo{}, fmt.Errorf("submit exactly one parser (found %d)", len(list))
	}
	p := list[0]
	if strings.TrimSpace(p.Name) == "" {
		return ParserInfo{}, fmt.Errorf("parser is missing a name")
	}
	if p.Source == "" {
		p.Source = strings.TrimSpace(yaml)
	}

	if err := s.ch.SaveParser(ctx, p.Name, p.Source); err != nil {
		return ParserInfo{}, fmt.Errorf("persist parser: %w", err)
	}

	s.mu.Lock()
	s.custom[p.Name] = p
	s.rebuild()
	s.mu.Unlock()

	return ParserInfo{Name: p.Name, LogType: p.LogType, Source: "custom", YAML: p.Source}, nil
}

// Delete removes a custom parser. Built-in parsers can't be deleted (a custom
// override of a built-in name is removed, revealing the built-in again).
func (s *ParserStore) Delete(ctx context.Context, name string) error {
	s.mu.RLock()
	_, isCustom := s.custom[name]
	s.mu.RUnlock()
	if !isCustom {
		if s.isBuiltin(name) {
			return fmt.Errorf("%q is a built-in parser and cannot be deleted", name)
		}
		return fmt.Errorf("parser %q not found", name)
	}

	if err := s.ch.DeleteParser(ctx, name); err != nil {
		return fmt.Errorf("delete parser: %w", err)
	}
	s.mu.Lock()
	delete(s.custom, name)
	s.rebuild()
	s.mu.Unlock()
	return nil
}

// LoadCustom loads persisted custom parsers from ClickHouse into the store. A
// row that no longer compiles is skipped (logged by the caller) rather than
// blocking startup.
func (s *ParserStore) LoadCustom(ctx context.Context) (int, error) {
	rows, err := s.ch.LoadParsers(ctx)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, row := range rows {
		list, err := ParseParserYAML([]byte(row.YAML))
		if err != nil || len(list) != 1 {
			continue
		}
		s.custom[row.Name] = list[0]
		n++
	}
	s.rebuild()
	return n, nil
}
