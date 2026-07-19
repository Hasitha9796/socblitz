package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// File Integrity Monitoring: periodically snapshot the configured paths and
// report created / modified / deleted files (with content hash) to the engine.

type fileState struct {
	sha  string
	size int64
}

func runFIM(ctx context.Context, cfg Config, fwd *Forwarder, agentID string) {
	if len(cfg.FIMPaths) == 0 {
		return
	}
	log.Printf("FIM monitoring %v every %s", cfg.FIMPaths, cfg.FIMInterval)
	prev := map[string]fileState{}
	first := true
	t := time.NewTicker(cfg.FIMInterval)
	defer t.Stop()
	for {
		cur := scanPaths(cfg.FIMPaths)
		var events []FimEvent
		for path, st := range cur {
			old, ok := prev[path]
			if !ok {
				if !first { // don't alert the whole baseline on first run
					events = append(events, fim(path, "created", st, agentID, cfg.Name))
				}
			} else if old.sha != st.sha {
				events = append(events, fim(path, "modified", st, agentID, cfg.Name))
			}
		}
		for path := range prev {
			if _, ok := cur[path]; !ok {
				events = append(events, fim(path, "deleted", fileState{}, agentID, cfg.Name))
			}
		}
		if len(events) > 0 {
			if err := fwd.PostFIM(ctx, events); err != nil {
				log.Printf("FIM post failed: %v", err)
			}
		}
		prev = cur
		first = false
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func fim(path, action string, st fileState, agentID, name string) FimEvent {
	return FimEvent{
		Path: path, Action: action, SHA256: st.sha, Size: st.size,
		AgentID: agentID, AgentName: name, Timestamp: time.Now().UTC(),
	}
}

func scanPaths(paths []string) map[string]fileState {
	out := map[string]fileState{}
	for _, root := range paths {
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			sum, size, err := hashFile(p)
			if err != nil {
				return nil
			}
			out[p] = fileState{sha: sum, size: size}
			return nil
		})
	}
	return out
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
