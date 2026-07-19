package main

import (
	"sync"
	"time"
)

// correlator.go — windowed evaluation for YARA-L rules that have a `match`
// clause.
//
// Chronicle's power beyond single-event matching is aggregation: "5 failed
// logins from the same IP within 5 minutes". The match clause names the join
// key(s) and the window; the condition counts events (`#e >= 5`). The
// correlator keeps, per rule and per join-key value, a sliding window of the
// timestamps of matching events, and fires once the count crosses the
// threshold — then re-arms after one window so a sustained attack produces
// periodic (not per-event) alerts.

type Correlator struct {
	mu    sync.Mutex
	rules []*YaraLRule
	state map[string]*winState
}

type winState struct {
	times   []time.Time
	firedAt time.Time
}

func NewCorrelator(set *YaraLSet) *Correlator {
	return &Correlator{rules: set.windowed, state: map[string]*winState{}}
}

func (c *Correlator) Count() int { return len(c.rules) }

// Observe feeds one normalized event to every windowed rule and returns any
// alerts that fired.
func (c *Correlator) Observe(u UDM, ev *Event) []Alert {
	if len(c.rules) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []Alert
	for _, r := range c.rules {
		// This subset correlates on a single event variable (covers brute
		// force, scanning, repeated-failure rules). Multi-event joins are
		// declared but evaluated as the first variable.
		evar := r.eventVars[0]
		matched, binds := r.matchEvent(evar, u)
		if !matched {
			continue
		}
		key, ok := groupKey(r, binds)
		if !ok {
			continue // a required join key wasn't present on this event
		}
		stateKey := r.Name + "\x00" + key

		st := c.state[stateKey]
		if st == nil {
			st = &winState{}
			c.state[stateKey] = st
		}
		ts := ev.Timestamp
		st.times = append(st.times, ts)
		pruneWindow(st, r.Match.window)

		_, min := r.countThreshold()
		if len(st.times) >= min && ts.Sub(st.firedAt) >= r.Match.window {
			st.firedAt = ts
			out = append(out, buildYaraLAlert(r, u, ev))
		}

		if len(st.times) == 0 {
			delete(c.state, stateKey)
		}
	}
	return out
}

// groupKey joins the match placeholder bindings into a single state key.
func groupKey(r *YaraLRule, binds map[string]string) (string, bool) {
	if len(r.Match.keys) == 0 {
		return "*", true
	}
	parts := make([]string, 0, len(r.Match.keys))
	for _, k := range r.Match.keys {
		v, ok := binds[k]
		if !ok || v == "" {
			return "", false
		}
		parts = append(parts, v)
	}
	return joinKey(parts), true
}

func joinKey(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "|"
		}
		out += p
	}
	return out
}

// pruneWindow drops timestamps older than `window` before the newest one, so a
// count reflects only events inside the sliding window.
func pruneWindow(st *winState, window time.Duration) {
	if len(st.times) == 0 {
		return
	}
	newest := st.times[len(st.times)-1]
	cutoff := newest.Add(-window)
	keep := st.times[:0]
	for _, t := range st.times {
		if !t.Before(cutoff) {
			keep = append(keep, t)
		}
	}
	st.times = keep
}
