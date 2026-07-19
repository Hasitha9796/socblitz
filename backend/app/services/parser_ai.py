"""
AI generation for SocBlitz engine assets — CBN parsers and YARA-L rules.

Given a raw log sample, ask the configured LLM (OpenAI-compatible: OPENAI_API_KEY
or LOCAL_LLM_URL / Ollama — same selection the dashboard agent uses) to write a
parser that normalizes the log to UDM, or a YARA-L detection rule that matches
on the normalized fields.

Every generated asset is validated against the engine before it's returned
(parsers via /parser/test, rules via /yaral/test). If the model produces
nothing usable — or no LLM is configured — a deterministic heuristic generator
takes over, so the feature always returns a working starting point.
"""
from __future__ import annotations

import re
from loguru import logger

from app.core.config import settings

# UDM vocabulary the model is allowed to target — kept in sync with the engine's
# parser guide (grok.go pattern library, udm.go event types).
GROK = "IP, NUMBER, INT, PORT, WORD, NOTSPACE, USERNAME, HOSTNAME, PATH, DATA, GREEDYDATA, QUOTEDSTRING, MAC, LOGLEVEL, TIME, SYSLOGTIMESTAMP"
UDM_PATHS = (
    "metadata.event_type, metadata.vendor_name, metadata.product_name, "
    "principal.ip, principal.port, principal.hostname, principal.user.userid, principal.process.command_line, "
    "target.ip, target.port, target.hostname, target.user.userid, target.url, target.process.command_line, target.file.full_path, "
    "network.direction, network.ip_protocol, network.application_protocol, network.http.method, network.http.response_code, "
    "security_result.action, security_result.category, security_result.severity, security_result.summary"
)
EVENT_TYPES = "USER_LOGIN, PROCESS_LAUNCH, NETWORK_CONNECTION, FILE_MODIFICATION, STATUS_UPDATE, SCAN_HOST, GENERIC_EVENT"


def _llm_target():
    """(base_url, model, headers) for the configured LLM, or None."""
    if settings.LOCAL_LLM_URL:
        return settings.LOCAL_LLM_URL.rstrip("/"), (settings.LOCAL_LLM_MODEL or "llama3"), {}
    if settings.OPENAI_API_KEY:
        return "https://api.openai.com/v1", settings.OPENAI_MODEL, {"Authorization": f"Bearer {settings.OPENAI_API_KEY}"}
    return None


async def _chat(system: str, user: str, timeout: float = 60.0) -> str | None:
    """One chat-completion turn; returns the assistant text (fences stripped)."""
    target = _llm_target()
    if not target:
        return None
    base_url, model, headers = target
    import httpx
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": 0,
                },
            )
            r.raise_for_status()
            return _strip_fences(r.json()["choices"][0]["message"]["content"])
    except Exception as e:
        logger.warning(f"LLM generation call failed: {e}")
        return None


def _strip_fences(s: str) -> str:
    s = (s or "").strip()
    # Pull the contents out of a ```lang … ``` block if the model wrapped it.
    m = re.search(r"```(?:\w+)?\s*\n(.*?)```", s, re.DOTALL)
    if m:
        return m.group(1).strip()
    return s


# ── syslog helpers (mirror the engine's RFC3164 split) ────────────────────────

_SYSLOG_RE = re.compile(
    r"^(?:<\d+>)?[A-Z][a-z]{2}\s+\d+\s[\d:]+\s+\S+\s+(?P<prog>[^:\[\s]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")


def _split_syslog(sample: str) -> tuple[str, str]:
    """Return (program, message) — message is the part parsers actually grok."""
    m = _SYSLOG_RE.match(sample.strip())
    if m:
        return m.group("prog"), m.group("msg")
    return "", sample.strip()


# ── parser generation ─────────────────────────────────────────────────────────

PARSER_SYSTEM = f"""You write CBN log parsers for SocBlitz. Output ONLY YAML — no prose, no ``` fences.

Grok patterns allowed: {GROK}.
Extract with %{{PATTERN:field}}, then reference it in set as '%{{field}}'.
UDM paths allowed: {UDM_PATHS}.
metadata.event_type is one of: {EVENT_TYPES}.
The syslog header (timestamp host program:) is already stripped — write grok for the MESSAGE part only.
Prefer kv for key=value logs; grok for positional logs.
The `check` gate decides when the parser runs. If the log has a syslog program, use `check:\n  program: <prog>`. If it has NO program (raw key=value appliance logs), gate on content instead: `check:\n  message: '/<distinctive_token>/'` (e.g. a unique key like devname=). Never gate on a program the log doesn't contain.

Example — for the message "Failed password for root from 1.2.3.4 port 22":
name: sshd
log_type: SSH
check:
  program: sshd
filter:
  - grok:
      source: message
      patterns:
        - '%{{WORD:result}} password for %{{USERNAME:user}} from %{{IP:src_ip}} port %{{PORT:port}}'
  - set:
      metadata.event_type: 'USER_LOGIN'
      metadata.vendor_name: 'OpenSSH'
      principal.ip: '%{{src_ip}}'
      principal.port: '%{{port}}'
      target.user.userid: '%{{user}}'
      security_result.action: 'BLOCK'
"""


def _parser_user(sample: str, hint: str) -> str:
    prog, msg = _split_syslog(sample)
    extra = f"\nProgram (syslog tag): {prog}" if prog else ""
    extra += f"\nMessage to parse: {msg}"
    if hint:
        extra += f"\nExtra guidance: {hint}"
    return f"Sample log line:\n{sample}\n{extra}\n\nWrite a parser that extracts the security-relevant fields."


def _heuristic_parser(sample: str, hint: str = "") -> str:
    """Deterministic fallback: derive a parser from the log's structure.

    Handles the common shapes — bracketed/bare IPs, HTTP request lines, and
    key=value pairs — mapping each onto the natural UDM field. IP-typed UDM
    fields are only set from values that actually look like IPs.
    """
    prog, msg = _split_syslog(sample)
    low = msg.lower()
    ip_re = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

    def _san(s: str) -> str:
        return re.sub(r"[^a-z0-9_]", "", (s or "").split("/")[0].lower())

    # key=value pairs (values may be quoted); strip quotes for inspection.
    kvs = {k: v.strip('"') for k, v in re.findall(r'(\w+)=("[^"]*"|[^\s;,]+)', msg)}

    # Gate + name. With a syslog program, gate on it. For a headerless log
    # (e.g. FortiGate/appliance key=value), gate on a distinctive content token
    # instead — gating on a program the event doesn't have would never match.
    ID_KEYS = ["devname", "devid", "product", "vendor", "hostname", "host",
               "type", "service", "logid", "app", "program", "proc"]
    if prog:
        name = _san(prog) or "app"
        check_block = f"check:\n  program: {prog}"
    else:
        gate_key = next((k for k in kvs if k.lower() in ID_KEYS), None) or next(iter(kvs), None)
        name = _san(kvs.get("devname") or kvs.get("product") or kvs.get("type") or gate_key or "app") or "app"
        if gate_key:
            check_block = f"check:\n  message: '/{re.escape(gate_key)}=/'"
        else:
            check_block = "check: {}"  # positional headerless log — no reliable gate

    sets: dict[str, str] = {"metadata.vendor_name": name}
    filters: list[str] = []

    # First IP anywhere (matches both bare 1.2.3.4 and host[1.2.3.4]).
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", msg):
        filters.append("  - grok:\n      source: message\n      patterns:\n        - '.*?%{IP:src_ip}'")
        sets["principal.ip"] = "%{src_ip}"

    # HTTP request line → method + url.
    if re.search(r"\b(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\b", msg):
        filters.append(
            "  - grok:\n      source: message\n      patterns:\n"
            "        - '(?P<http_method>GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS) (?P<http_url>%{NOTSPACE})'")
        sets["network.http.method"] = "%{http_method}"
        sets["target.url"] = "%{http_url}"

    # key=value pairs.
    if kvs:
        filters.append("  - kv:\n      source: message")
        key_map = {
            "principal.ip": ("src", "source", "srcip", "client", "clientip", "ip", "remote"),
            "target.ip": ("dst", "dest", "dstip", "destination"),
            "principal.port": ("spt", "sport", "srcport"),
            "target.port": ("dpt", "dport", "dstport", "port"),
            "target.user.userid": ("user", "username", "account", "uid", "usr", "to"),
            "principal.user.userid": ("from", "sender"),
            "security_result.action": ("action", "act", "status", "result", "outcome", "disposition"),
            "network.ip_protocol": ("proto", "protocol"),
        }
        for udm_path, keys in key_map.items():
            for k, v in kvs.items():
                if k.lower() in keys:
                    if udm_path.endswith(".ip") and not ip_re.match(v):
                        continue
                    sets.setdefault(udm_path, f"%{{{k}}}")
                    break

    # event_type by keyword / structure.
    net_keys = any(k.lower() in ("srcip", "dstip", "dstport", "srcport", "proto", "dpt", "spt", "src", "dst")
                   for k in kvs)
    if any(k in low for k in ("login", "auth", "password", "logon")):
        sets["metadata.event_type"] = "USER_LOGIN"
    elif "command=" in low or "sudo" in low or " exec" in low:
        sets["metadata.event_type"] = "PROCESS_LAUNCH"
    elif (net_keys or re.search(r"\b(get|post|put|delete|head|patch)\b", low)
          or any(k in low for k in ("traffic", "firewall", "connect", "connection", "reject", "rcpt", "packet", "denied", "allow"))):
        sets["metadata.event_type"] = "NETWORK_CONNECTION"
    else:
        sets["metadata.event_type"] = "GENERIC_EVENT"

    if not filters:
        filters.append("  - kv:\n      source: message")
    set_lines = "\n".join(f"      {k}: '{v}'" for k, v in sets.items())
    return (
        f"name: {name}\n"
        f"log_type: {name.upper()}\n"
        f"{check_block}\n"
        f"filter:\n" + "\n".join(filters) + f"\n  - set:\n{set_lines}"
    )


async def generate_parser(sample: str, hint: str = "") -> dict:
    from app.connectors.registry import EngineClient

    llm_yaml = await _chat(PARSER_SYSTEM, _parser_user(sample, hint), timeout=120.0)
    source = "heuristic"
    yaml_text = None
    if llm_yaml and "name:" in llm_yaml and "filter:" in llm_yaml:
        yaml_text, source = llm_yaml, "llm"

    if not yaml_text:
        yaml_text = _heuristic_parser(sample, hint)

    # Validate against the engine; if the LLM's parser is invalid or extracts
    # nothing, fall back to the heuristic and re-test.
    engine = EngineClient()
    tested = None
    try:
        tested = await engine.test_parser(sample, yaml=yaml_text)
        if source == "llm" and (tested.get("error") or not tested.get("matched")):
            logger.info("LLM parser didn't validate; using heuristic")
            yaml_text = _heuristic_parser(sample, hint)
            source = "heuristic (llm output invalid)"
            tested = await engine.test_parser(sample, yaml=yaml_text)
    except Exception as e:
        logger.warning(f"parser validation skipped: {e}")

    return {"yaml": yaml_text, "source": source, "tested": tested}


# ── YARA-L rule generation ────────────────────────────────────────────────────

YARAL_SYSTEM = """You write YARA-L detection rules for the SocBlitz engine.
Output ONLY the rule text — no prose, no markdown fences.

Format:
rule <lowercase_name> {
  meta:
    author = "socblitz"
    description = "<one line>"
    severity = "LOW|MEDIUM|HIGH|CRITICAL"
    tactic = "<mitre tactic, e.g. credential_access>"
    technique = "T1110"
  events:
    $e.<udm.path> = "value"        // equality; also !=, > N, or =~ /regex/
    $e.principal.ip = $ip          // bind a placeholder to correlate/group
  match:                           // OPTIONAL — only for aggregation rules
    $ip over 5m
  condition:
    #e >= 5                        // event count; or just  $e  for single-event

Rules:
- Match ONLY on UDM field paths that the event actually has (given below).
- For "N events within a time window" detections (brute force, scans), add a
  match clause and a count condition (#e >= N). For a single suspicious event,
  omit match and use  condition: $e.
"""


async def generate_yaral(sample: str, hint: str = "") -> dict:
    from app.connectors.registry import EngineClient

    engine = EngineClient()
    # Normalize first so the rule references fields the event really produces.
    norm = {}
    try:
        norm = await engine.normalize(sample)
    except Exception as e:
        logger.warning(f"normalize for rule-gen failed: {e}")

    event_type = norm.get("event_type", "GENERIC_EVENT")
    fields = norm.get("fields", {})
    field_lines = "\n".join(f"  {k} = {v}" for k, v in sorted(fields.items()))

    user = (
        f"This log normalizes to event_type={event_type} with these UDM fields:\n"
        f"{field_lines or '  (no fields)'}\n\nRaw log:\n{sample}\n\n"
        "Write one detection rule for a security-relevant condition in this log."
    )
    if hint:
        user += f"\nExtra guidance: {hint}"

    rule_text = await _chat(YARAL_SYSTEM, user, timeout=120.0)
    source = "llm"
    if not rule_text or "rule " not in rule_text or "events:" not in rule_text:
        rule_text = _heuristic_yaral(event_type, fields)
        source = "heuristic"

    tested = None
    try:
        tested = await engine.test_yaral(rule_text, [sample])
        if source == "llm" and tested.get("error"):
            rule_text = _heuristic_yaral(event_type, fields)
            source = "heuristic (llm output invalid)"
            tested = await engine.test_yaral(rule_text, [sample])
    except Exception as e:
        logger.warning(f"rule validation skipped: {e}")

    return {"rule": rule_text, "source": source, "event_type": event_type, "tested": tested}


def _heuristic_yaral(event_type: str, fields: dict) -> str:
    """Single-event rule keyed on the event_type plus one notable predicate."""
    preds = [f'    $e.metadata.event_type = "{event_type}"']
    sev, tactic, tech, name = "LOW", "discovery", "T1592", "generic_event"
    action = fields.get("security_result.action", "")
    if event_type == "USER_LOGIN" and action.upper() == "BLOCK":
        preds.append('    $e.security_result.action = "BLOCK"')
        sev, tactic, tech, name = "MEDIUM", "credential_access", "T1110", "failed_login"
    elif event_type == "USER_LOGIN" and fields.get("target.user.userid", "").lower() == "root":
        preds.append('    $e.target.user.userid = "root"')
        sev, tactic, tech, name = "MEDIUM", "initial_access", "T1078", "root_login"
    elif event_type == "PROCESS_LAUNCH":
        sev, tactic, tech, name = "LOW", "privilege_escalation", "T1548", "process_launch"
    elif event_type == "NETWORK_CONNECTION":
        sev, tactic, tech, name = "MEDIUM", "reconnaissance", "T1595", "network_connection"
    body = "\n".join(preds)
    return (
        f"rule {name} {{\n"
        f"  meta:\n    author = \"socblitz\"\n    description = \"Auto-generated detection for {event_type}\"\n"
        f"    severity = \"{sev}\"\n    tactic = \"{tactic}\"\n    technique = \"{tech}\"\n"
        f"  events:\n{body}\n"
        f"  condition:\n    $e\n}}"
    )
