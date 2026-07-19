package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"
)

type enrollBody struct {
	Hostname  string `json:"hostname"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	OS        string `json:"os"`
	OSVersion string `json:"os_version"`
	Version   string `json:"version"`
}

const agentVersion = "0.1.0"

// enroll registers this host with the engine and returns the assigned agent id.
// It retries until the engine is reachable (engine may start after the agent).
func enroll(ctx context.Context, cfg Config) (string, error) {
	host, _ := os.Hostname()
	body, _ := json.Marshal(enrollBody{
		Hostname: host, Name: cfg.Name, IP: localIP(),
		OS: runtime.GOOS, OSVersion: osVersion(), Version: agentVersion,
	})
	client := &http.Client{Timeout: 15 * time.Second}
	backoff := time.Second
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EngineURL+"/enroll", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if cfg.EnrollKey != "" {
			req.Header.Set("X-Enroll-Key", cfg.EnrollKey)
		}
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode < 300 {
			var out struct {
				AgentID string `json:"agent_id"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if out.AgentID != "" {
				return out.AgentID, nil
			}
		}
		if resp != nil {
			resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("enroll cancelled")
		case <-time.After(backoff):
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
	}
}

// heartbeat pings the engine periodically so the agent shows "active".
func heartbeat(ctx context.Context, cfg Config, agentID string) {
	client := &http.Client{Timeout: 10 * time.Second}
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
				cfg.EngineURL+"/heartbeat?agent_id="+agentID, nil)
			if cfg.EnrollKey != "" {
				req.Header.Set("X-Enroll-Key", cfg.EnrollKey)
			}
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}
}
