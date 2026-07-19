package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// Vulnerability detection: the agent reports installed packages; the engine
// matches them against a CVE feed and writes findings to wazuh_vulnerabilities.
//
// The feed here is a small local JSON map (package -> CVEs) as a working
// stand-in. The real extension point is loadVulnFeed(): swap it for NVD/OSV
// ingestion (by product/version range) without touching the ingest path.

type CVE struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score"`
	MaxFixed string  `json:"max_fixed_version"` // optional; informational for now
}

type VulnFeed struct {
	byPackage map[string][]CVE
}

func loadVulnFeed(path string) (*VulnFeed, error) {
	vf := &VulnFeed{byPackage: map[string][]CVE{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return vf, nil // empty feed is fine
		}
		return nil, err
	}
	if err := json.Unmarshal(data, &vf.byPackage); err != nil {
		return nil, err
	}
	return vf, nil
}

func (vf *VulnFeed) lookup(pkg string) []CVE { return vf.byPackage[pkg] }

type invPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type inventoryReq struct {
	AgentID   string       `json:"agent_id"`
	AgentName string       `json:"agent_name"`
	Packages  []invPackage `json:"packages"`
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req inventoryReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	now := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	var rows []chVulnRow
	for _, p := range req.Packages {
		for _, cve := range s.vuln.lookup(p.Name) {
			raw, _ := json.Marshal(map[string]any{
				"agent":   map[string]string{"id": req.AgentID, "name": req.AgentName},
				"package": map[string]string{"name": p.Name, "version": p.Version},
				"vulnerability": map[string]any{"cve": cve.ID, "severity": cve.Severity,
					"score": map[string]float64{"base": cve.Score}},
			})
			rows = append(rows, chVulnRow{
				Timestamp: now, AgentID: req.AgentID, AgentName: req.AgentName,
				VulnID: cve.ID, Severity: cve.Severity, Score: cve.Score,
				Package: p.Name, Raw: string(raw),
			})
		}
	}
	s.touchFromEvent(req.AgentID)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.ch.InsertVulns(ctx, rows); err != nil {
		http.Error(w, "insert failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]int{"findings": len(rows), "packages": len(req.Packages)})
}
