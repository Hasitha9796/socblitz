-- ─────────────────────────────────────────────────────────────────────────────
-- SocBlitz ClickHouse schema
--
-- Replaces the Wazuh Indexer (OpenSearch) as the analytics store. Wazuh Manager
-- writes /var/ossec/logs/alerts/alerts.json; Vector tails that file and inserts
-- rows here (see config/vector/vector.toml). The backend queries these tables
-- through ClickHouseClient, which translates the OpenSearch-DSL bodies the
-- dashboard generators build into SQL.
--
-- Design notes:
--   * Typed columns exist for every field the dashboards aggregate on, so
--     GROUP BY is cheap. The full original alert JSON is kept in `raw` so the
--     live event view and single-event lookup can return the complete document
--     (the OpenSearch `_source`).
--   * Array fields (rule.groups, MITRE tactic/technique) are Array(String) and
--     are aggregated with arrayJoin() / filtered with hasAny().
--   * Vulnerabilities have no managed "current state" index here the way the
--     indexer provided one, so we approximate it: vuln rows land in a
--     ReplacingMergeTree keyed by (agent_id, package_name, vuln_id); querying
--     with FINAL collapses repeat detections of the same open finding to one
--     row. This mirrors "open vulnerabilities" closely enough for the
--     dashboards, with the caveat that a *resolved* vuln is not tombstoned.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS wazuh;

-- ── Alerts ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wazuh.wazuh_alerts
(
    alert_id          String,                       -- Wazuh top-level `id` (e.g. 1700000000.12345)
    timestamp         DateTime64(3),
    rule_id           String,
    rule_level        UInt16,
    rule_description  String,
    rule_groups       Array(String),
    mitre_tactic      Array(String),
    mitre_technique   Array(String),
    agent_id          String,
    agent_name        String,
    data_srcip        String,
    data_dstuser      String,
    raw               String,                        -- full original alert JSON (= OpenSearch _source)
    ingested_at       DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, rule_id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY        -- retention; tune or drop as needed
SETTINGS index_granularity = 8192;

-- ── Vulnerabilities ────────────────────────────────────────────────────────
-- ReplacingMergeTree(timestamp): within one (agent, package, cve) key the row
-- with the newest timestamp wins after merges. Query with FINAL to read the
-- deduplicated "current" set.
CREATE TABLE IF NOT EXISTS wazuh.wazuh_vulnerabilities
(
    alert_id          String,
    timestamp         DateTime64(3),
    agent_id          String,
    agent_name        String,
    vuln_id           String,                        -- CVE
    vuln_severity     String,
    vuln_score_base   Float32,
    package_name      String,
    raw               String,
    ingested_at       DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(timestamp)
ORDER BY (agent_id, package_name, vuln_id)
SETTINGS index_granularity = 8192;

-- ── Agents ───────────────────────────────────────────────────────────────────
-- Registry populated by socblitz-engine on enroll/heartbeat. ReplacingMergeTree
-- keeps the newest row per agent_id (by updated_at); query with FINAL.
CREATE TABLE IF NOT EXISTS wazuh.agents
(
    agent_id     String,
    name         String,
    hostname     String,
    ip           String,
    os           String,          -- linux | windows | macos | unknown
    os_version   String,
    version      String,          -- agent version
    group        String,
    last_seen    DateTime,
    enrolled_at  DateTime,
    updated_at   DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY agent_id
SETTINGS index_granularity = 8192;

-- User-defined CBN parsers created/edited through the Engine UI. The engine
-- also CREATEs this on startup; kept here so a fresh cluster has it up front.
-- ReplacingMergeTree(updated_at) keeps the newest row per name; deleted=1 is a
-- soft-delete tombstone. Query with FINAL WHERE deleted = 0.
CREATE TABLE IF NOT EXISTS wazuh.engine_parsers
(
    name       String,
    yaml       String,
    deleted    UInt8 DEFAULT 0,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY name
SETTINGS index_granularity = 8192;
