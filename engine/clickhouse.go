package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CHClient writes alert rows into ClickHouse over the HTTP interface using
// JSONEachRow — the same tables (wazuh.wazuh_alerts / wazuh_vulnerabilities)
// the socblitz backend already queries.
type CHClient struct {
	url  string
	user string
	pass string
	http *http.Client
}

func NewCHClient(url, user, pass string) *CHClient {
	return &CHClient{url: url, user: user, pass: pass, http: &http.Client{Timeout: 15 * time.Second}}
}

// chAlertRow is the JSONEachRow shape; keys must equal the column names.
type chAlertRow struct {
	AlertID     string   `json:"alert_id"`
	Timestamp   string   `json:"timestamp"`
	RuleID      string   `json:"rule_id"`
	RuleLevel   int      `json:"rule_level"`
	RuleDesc    string   `json:"rule_description"`
	RuleGroups  []string `json:"rule_groups"`
	MitreTactic []string `json:"mitre_tactic"`
	MitreTech   []string `json:"mitre_technique"`
	AgentID     string   `json:"agent_id"`
	AgentName   string   `json:"agent_name"`
	DataSrcIP   string   `json:"data_srcip"`
	DataDstUser string   `json:"data_dstuser"`
	Raw         string   `json:"raw"`
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (c *CHClient) InsertAlerts(ctx context.Context, alerts []Alert) error {
	if len(alerts) == 0 {
		return nil
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, a := range alerts {
		row := chAlertRow{
			AlertID:     a.AlertID,
			Timestamp:   a.Timestamp.UTC().Format("2006-01-02 15:04:05.000"),
			RuleID:      a.RuleID,
			RuleLevel:   a.RuleLevel,
			RuleDesc:    a.Description,
			RuleGroups:  nz(a.Groups),
			MitreTactic: nz(a.Tactics),
			MitreTech:   nz(a.Techniques),
			AgentID:     a.AgentID,
			AgentName:   a.AgentName,
			DataSrcIP:   a.SrcIP,
			DataDstUser: a.DstUser,
			Raw:         a.Raw,
		}
		if err := enc.Encode(&row); err != nil {
			return err
		}
	}
	return c.insert(ctx, "wazuh.wazuh_alerts", &body)
}

func (c *CHClient) insert(ctx context.Context, table string, body *bytes.Buffer) error {
	q := fmt.Sprintf("INSERT INTO %s FORMAT JSONEachRow", table)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/?query="+urlQuery(q), body)
	if err != nil {
		return err
	}
	req.Header.Set("X-ClickHouse-User", c.user)
	req.Header.Set("X-ClickHouse-Key", c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("clickhouse insert %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// ── vulnerabilities ──────────────────────────────────────────────────────────

type chVulnRow struct {
	AlertID   string  `json:"alert_id"`
	Timestamp string  `json:"timestamp"`
	AgentID   string  `json:"agent_id"`
	AgentName string  `json:"agent_name"`
	VulnID    string  `json:"vuln_id"`
	Severity  string  `json:"vuln_severity"`
	Score     float64 `json:"vuln_score_base"`
	Package   string  `json:"package_name"`
	Raw       string  `json:"raw"`
}

func (c *CHClient) InsertVulns(ctx context.Context, rows []chVulnRow) error {
	if len(rows) == 0 {
		return nil
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for i := range rows {
		if rows[i].Timestamp == "" {
			rows[i].Timestamp = time.Now().UTC().Format("2006-01-02 15:04:05.000")
		}
		if err := enc.Encode(&rows[i]); err != nil {
			return err
		}
	}
	return c.insert(ctx, "wazuh.wazuh_vulnerabilities", &body)
}

// ── agents ───────────────────────────────────────────────────────────────────

func (c *CHClient) UpsertAgent(ctx context.Context, a AgentInfo) error {
	row := map[string]any{
		"agent_id": a.ID, "name": a.Name, "hostname": a.Hostname, "ip": a.IP,
		"os": a.OS, "os_version": a.OSVersion, "version": a.Version, "group": a.Group,
		"last_seen": a.LastSeen.UTC().Format("2006-01-02 15:04:05"),
		"enrolled_at": a.EnrolledAt.UTC().Format("2006-01-02 15:04:05"),
	}
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(row); err != nil {
		return err
	}
	return c.insert(ctx, "wazuh.agents", &body)
}

// Touch updates last_seen (re-inserts newest row; ReplacingMergeTree collapses).
func (c *CHClient) Touch(ctx context.Context, agentID string) {
	rows, err := c.selectAgents(ctx, agentID)
	if err != nil || len(rows) == 0 {
		return
	}
	a := rows[0]
	a.LastSeen = time.Now().UTC()
	_ = c.UpsertAgent(ctx, a)
}

func (c *CHClient) ListAgents(ctx context.Context) ([]AgentInfo, error) {
	return c.selectAgents(ctx, "")
}

func (c *CHClient) selectAgents(ctx context.Context, id string) ([]AgentInfo, error) {
	where := "1"
	if id != "" {
		where = "agent_id = " + sqlStr(id)
	}
	sql := "SELECT agent_id, name, hostname, ip, os, os_version, version, group, " +
		"toString(last_seen) AS last_seen, toString(enrolled_at) AS enrolled_at " +
		"FROM wazuh.agents FINAL WHERE " + where
	rows, err := c.queryRows(ctx, sql)
	if err != nil {
		return nil, err
	}
	out := make([]AgentInfo, 0, len(rows))
	for _, r := range rows {
		ls, _ := time.Parse("2006-01-02 15:04:05", r["last_seen"])
		en, _ := time.Parse("2006-01-02 15:04:05", r["enrolled_at"])
		out = append(out, AgentInfo{
			ID: r["agent_id"], Name: r["name"], Hostname: r["hostname"], IP: r["ip"],
			OS: r["os"], OSVersion: r["os_version"], Version: r["version"], Group: r["group"],
			LastSeen: ls, EnrolledAt: en,
		})
	}
	return out, nil
}

func (c *CHClient) queryRows(ctx context.Context, sql string) ([]map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.url+"/?query="+urlQuery(sql+" FORMAT JSON"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-ClickHouse-User", c.user)
	req.Header.Set("X-ClickHouse-Key", c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("clickhouse query %d: %s", resp.StatusCode, string(b))
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	out := make([]map[string]string, 0, len(parsed.Data))
	for _, row := range parsed.Data {
		m := map[string]string{}
		for k, v := range row {
			if s, ok := v.(string); ok {
				m[k] = s
			} else {
				m[k] = fmt.Sprintf("%v", v)
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// ── custom parsers (user-defined, edited through the UI) ──────────────────────
//
// User-defined CBN parsers live in ClickHouse so they survive engine restarts
// without a writable volume. ReplacingMergeTree(updated_at) keeps the newest
// row per name; a soft-delete row (deleted=1) tombstones one. Query with FINAL.

func (c *CHClient) EnsureParserTable(ctx context.Context) error {
	ddl := `CREATE TABLE IF NOT EXISTS wazuh.engine_parsers
(
    name       String,
    yaml       String,
    deleted    UInt8 DEFAULT 0,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY name
SETTINGS index_granularity = 8192`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/?query="+urlQuery(ddl), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-ClickHouse-User", c.user)
	req.Header.Set("X-ClickHouse-Key", c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("clickhouse create parser table %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// StoredParser is one row of the custom-parser table.
type StoredParser struct {
	Name string
	YAML string
}

func (c *CHClient) LoadParsers(ctx context.Context) ([]StoredParser, error) {
	sql := "SELECT name, yaml FROM wazuh.engine_parsers FINAL WHERE deleted = 0 ORDER BY name"
	rows, err := c.queryRows(ctx, sql)
	if err != nil {
		return nil, err
	}
	out := make([]StoredParser, 0, len(rows))
	for _, r := range rows {
		out = append(out, StoredParser{Name: r["name"], YAML: r["yaml"]})
	}
	return out, nil
}

func (c *CHClient) SaveParser(ctx context.Context, name, yaml string) error {
	return c.writeParserRow(ctx, name, yaml, 0)
}

func (c *CHClient) DeleteParser(ctx context.Context, name string) error {
	return c.writeParserRow(ctx, name, "", 1)
}

func (c *CHClient) writeParserRow(ctx context.Context, name, yaml string, deleted int) error {
	row := map[string]any{
		"name":       name,
		"yaml":       yaml,
		"deleted":    deleted,
		"updated_at": time.Now().UTC().Format("2006-01-02 15:04:05"),
	}
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(row); err != nil {
		return err
	}
	return c.insert(ctx, "wazuh.engine_parsers", &body)
}

func (c *CHClient) Ping(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/?query="+urlQuery("SELECT 1"), nil)
	req.Header.Set("X-ClickHouse-User", c.user)
	req.Header.Set("X-ClickHouse-Key", c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("clickhouse ping %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
