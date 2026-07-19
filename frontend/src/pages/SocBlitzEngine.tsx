import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play, Wand2, Braces, Copy, CheckCircle2, XCircle, Loader2,
  Layers, ShieldAlert, Clock, Boxes, Plus, Save, Trash2, FlaskConical, Lock, Sparkles,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api, useAuthStore } from '../stores/auth'

type Tab = 'test' | 'rulegen' | 'normalize' | 'yaral' | 'parsers'

const LEVEL_COLOR = (lvl: number) =>
  lvl >= 12 ? '#f43f5e' : lvl >= 8 ? '#f97316' : lvl >= 4 ? '#f59e0b' : '#67e8f9'

function FieldsTable({ fields }: { fields: Record<string, string> | null | undefined }) {
  const entries = Object.entries(fields || {})
  if (!entries.length) return <p className="page-sub" style={{ margin: 0 }}>No fields extracted.</p>
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k} style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <td style={{ padding: '6px 10px', color: '#94a3b8', fontFamily: 'monospace', width: 160 }}>{k}</td>
            <td style={{ padding: '6px 10px', fontFamily: 'monospace' }}>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function AlertList({ alerts }: { alerts: any[] }) {
  if (!alerts?.length)
    return (
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', color: '#94a3b8' }}>
        <XCircle size={16} /> No rule matched this line.
      </div>
    )
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {alerts.map((a, i) => (
        <div key={i} className="card" style={{ padding: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{
              background: LEVEL_COLOR(a.RuleLevel), color: '#0b1020', fontWeight: 700,
              borderRadius: 6, padding: '2px 8px', fontSize: 12,
            }}>L{a.RuleLevel}</span>
            <span style={{ fontFamily: 'monospace', color: '#93c5fd' }}>{a.RuleID}</span>
            <span style={{ fontWeight: 600 }}>{a.Description}</span>
          </div>
          <div style={{ marginTop: 6, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {(a.Groups || []).map((g: string) => (
              <span key={g} style={{ fontSize: 11, background: 'rgba(96,165,250,.15)', color: '#93c5fd', borderRadius: 4, padding: '2px 6px' }}>{g}</span>
            ))}
            {(a.Techniques || []).map((t: string) => (
              <span key={t} style={{ fontSize: 11, background: 'rgba(192,132,252,.15)', color: '#c084fc', borderRadius: 4, padding: '2px 6px' }}>{t}</span>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Test tab ──────────────────────────────────────────────────────────────────
function TestTab() {
  const [message, setMessage] = useState(
    'Oct 12 18:00:01 web-01 sshd[999]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2')
  const [result, setResult] = useState<any>(null)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setBusy(true)
    try {
      const r = await api.engineTestLog(message)
      setResult(r.data)
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Engine unavailable')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      <div className="card">
        <p className="section-heading">Raw log line</p>
        <textarea className="input" rows={5} value={message} onChange={(e) => setMessage(e.target.value)}
          style={{ fontFamily: 'monospace', resize: 'vertical' }} />
        <button className="btn-primary" onClick={run} disabled={busy} style={{ marginTop: 10 }}>
          {busy ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />} Run test
        </button>
      </div>
      <div className="card">
        <p className="section-heading">Decoded event</p>
        {!result ? <p className="page-sub" style={{ margin: 0 }}>Run a line to see how the engine decodes and matches it.</p> : (
          <>
            <div style={{ fontSize: 13, marginBottom: 8 }}>
              <span style={{ color: '#94a3b8' }}>program </span>
              <span style={{ fontFamily: 'monospace', color: '#93c5fd' }}>{result.event?.program || '—'}</span>
            </div>
            <FieldsTable fields={result.event?.fields} />
            <p className="section-heading" style={{ marginTop: 16 }}>Matched rules ({result.alerts?.length || 0})</p>
            <AlertList alerts={result.alerts || []} />
          </>
        )}
      </div>
    </div>
  )
}

// ── Rule Generation tab ───────────────────────────────────────────────────────
function RuleGenTab() {
  const [form, setForm] = useState({
    id: '100001', level: 7, description: 'Custom detection',
    program: 'sshd', match: 'Failed password', groups: 'authentication_failed,custom',
    mitre_techniques: 'T1110', mitre_tactics: 'Credential Access',
  })
  const [sample, setSample] = useState(
    'Oct 12 18:00:01 web-01 sshd[999]: Failed password for root from 203.0.113.5 port 22 ssh2')
  const [result, setResult] = useState<any>(null)
  const [busy, setBusy] = useState(false)

  const set = (k: string, v: any) => setForm((f) => ({ ...f, [k]: v }))
  const list = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean)

  const rule = {
    id: form.id,
    level: Number(form.level) || 0,
    description: form.description,
    program: form.program || undefined,
    match: form.match || undefined,
    groups: list(form.groups),
    mitre_techniques: list(form.mitre_techniques),
    mitre_tactics: list(form.mitre_tactics),
  }
  const ruleJSON = JSON.stringify(rule, null, 2)

  const prefill = async () => {
    try {
      const r = await api.engineTestLog(sample)
      const ev = r.data.event
      if (ev?.program) set('program', ev.program)
      toast.success(`Prefilled program "${ev?.program || '?'}" from sample`)
    } catch { toast.error('Could not decode sample') }
  }

  const test = async () => {
    setBusy(true)
    try {
      const r = await api.engineTestRule(rule, sample)
      setResult(r.data)
      if (r.data.error) toast.error(r.data.error)
      else if (r.data.matched) toast.success('Rule matched the sample')
      else toast('Rule did not match', { icon: '∅' })
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Engine unavailable')
    } finally {
      setBusy(false)
    }
  }

  const copy = () => { navigator.clipboard.writeText(ruleJSON); toast.success('Rule JSON copied') }

  const field = (label: string, key: keyof typeof form, mono = false) => (
    <div>
      <label className="page-sub">{label}</label>
      <input className="input" value={form[key] as any} onChange={(e) => set(key, e.target.value)}
        style={mono ? { fontFamily: 'monospace' } : undefined} />
    </div>
  )

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      <div className="card">
        <p className="section-heading">Rule definition</p>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          {field('Rule ID', 'id', true)}
          {field('Level (0–15)', 'level')}
        </div>
        {field('Description', 'description')}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          {field('Program (optional)', 'program', true)}
          {field('Match regex (optional)', 'match', true)}
        </div>
        {field('Groups (comma-separated)', 'groups')}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          {field('MITRE techniques', 'mitre_techniques', true)}
          {field('MITRE tactics', 'mitre_tactics')}
        </div>

        <p className="section-heading" style={{ marginTop: 16 }}>Sample log to test against</p>
        <textarea className="input" rows={3} value={sample} onChange={(e) => setSample(e.target.value)}
          style={{ fontFamily: 'monospace', resize: 'vertical' }} />
        <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
          <button className="btn-primary" onClick={test} disabled={busy}>
            {busy ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />} Test rule
          </button>
          <button className="btn-secondary" onClick={prefill}><Wand2 size={15} /> Prefill from sample</button>
        </div>
      </div>

      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <p className="section-heading" style={{ margin: 0 }}><Braces size={14} style={{ verticalAlign: -2 }} /> Generated rule (JSON)</p>
          <button className="btn-ghost" onClick={copy}><Copy size={14} /> Copy</button>
        </div>
        <pre style={{
          background: '#0b1020', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8,
          padding: 12, fontSize: 12.5, overflowX: 'auto', maxHeight: 300,
        }}>{ruleJSON}</pre>
        <p className="page-sub">Drop this into <code>engine/rules/*.json</code> and restart the engine to make it permanent.</p>

        {result && (
          <div style={{ marginTop: 12 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', color: result.matched ? '#22c55e' : '#f43f5e', marginBottom: 8 }}>
              {result.matched ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
              {result.error ? result.error : result.matched ? 'Matched the sample' : 'Did not match'}
            </div>
            {result.alert && <AlertList alerts={[result.alert]} />}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Normalize (UDM) tab ─────────────────────────────────────────────────────
// Chronicle-style: a raw log is normalized by CBN parsers into a UDM record.
function NormalizeTab() {
  const [message, setMessage] = useState(
    'Oct 12 18:00:01 web-01 sshd[999]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2')
  const [result, setResult] = useState<any>(null)
  const [busy, setBusy] = useState(false)

  const samples = [
    ['SSH failure', 'Oct 12 18:00:01 web-01 sshd[999]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2'],
    ['SSH root success', 'Oct 12 18:06:00 web-01 sshd[800]: Accepted password for root from 10.0.0.5 port 22 ssh2'],
    ['sudo command', 'Oct 12 18:10:00 web-01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt install nmap'],
    ['iptables drop', 'Oct 12 18:12:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.7 DST=10.0.0.1 PROTO=TCP SPT=51000 DPT=22'],
  ]

  const run = async () => {
    setBusy(true)
    try {
      const r = await api.engineNormalize(message)
      setResult(r.data)
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Engine unavailable')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      <div className="card">
        <p className="section-heading">Raw log line</p>
        <textarea className="input" rows={5} value={message} onChange={(e) => setMessage(e.target.value)}
          style={{ fontFamily: 'monospace', resize: 'vertical' }} />
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, margin: '8px 0' }}>
          {samples.map(([label, s]) => (
            <button key={label} className="btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }}
              onClick={() => setMessage(s)}>{label}</button>
          ))}
        </div>
        <button className="btn-primary" onClick={run} disabled={busy}>
          {busy ? <Loader2 size={15} className="animate-spin" /> : <Layers size={15} />} Normalize to UDM
        </button>
        <p className="page-sub" style={{ marginTop: 10 }}>
          CBN parsers (grok/kv/json) map the raw log onto the Unified Data Model — the same
          normalization Chronicle applies before detection.
        </p>
      </div>
      <div className="card">
        <p className="section-heading">UDM event</p>
        {!result ? <p className="page-sub" style={{ margin: 0 }}>Normalize a line to see its UDM record.</p> : (
          <>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
              <span style={{ fontSize: 11, color: '#94a3b8' }}>event_type</span>
              <span style={{ background: 'rgba(96,165,250,.15)', color: '#93c5fd', borderRadius: 6, padding: '2px 10px', fontFamily: 'monospace', fontWeight: 600 }}>
                {result.event_type || 'GENERIC_EVENT'}
              </span>
            </div>
            {result.parsers?.length > 0 && (
              <div style={{ marginBottom: 10, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                <span style={{ fontSize: 11, color: '#94a3b8', alignSelf: 'center' }}>parsers</span>
                {result.parsers.map((d: string) => (
                  <span key={d} style={{ fontSize: 11, background: 'rgba(34,197,94,.15)', color: '#4ade80', borderRadius: 4, padding: '2px 6px' }}>{d}</span>
                ))}
              </div>
            )}
            <FieldsTable fields={result.fields} />
          </>
        )}
      </div>
    </div>
  )
}

// ── YARA-L tab ──────────────────────────────────────────────────────────────
const DEFAULT_YARAL = `rule ssh_brute_force {
  meta:
    author = "socblitz"
    description = "SSH brute force: 5+ failed logins from one source in 5m"
    severity = "HIGH"
    tactic = "credential_access"
    technique = "T1110"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $srcip
  match:
    $srcip over 5m
  condition:
    #e >= 5
}`

const DEFAULT_YARAL_LINES = Array.from({ length: 5 }, (_, i) =>
  `Oct 12 18:00:0${i} web-01 sshd[70${i}]: Failed password for root from 45.155.205.99 port 22 ssh2`).join('\n')

function YaraLTab() {
  const [rule, setRule] = useState(DEFAULT_YARAL)
  const [lines, setLines] = useState(DEFAULT_YARAL_LINES)
  const [result, setResult] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  const [genBusy, setGenBusy] = useState(false)

  const generateRule = async () => {
    const first = lines.split('\n').map((l) => l.trim()).filter(Boolean)[0]
    if (!first) { toast.error('Add a sample log line to generate from'); return }
    setGenBusy(true)
    try {
      const r = await api.engineGenerateYaraL(first)
      setRule(r.data.rule || '')
      toast.success(`Rule generated (${r.data.source}) for ${r.data.event_type}`)
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Generation failed')
    } finally { setGenBusy(false) }
  }

  const { data: yaralRules } = useQuery({
    queryKey: ['engine-yaral-rules'],
    queryFn: () => api.engineYaraLRules().then((r) => r.data),
  })

  const run = async () => {
    setBusy(true)
    try {
      const messages = lines.split('\n').map((l) => l.trim()).filter(Boolean)
      const r = await api.engineTestYaraL(rule, messages)
      setResult(r.data)
      if (r.data.error) toast.error(r.data.error)
      else if (r.data.matched) toast.success(`${r.data.alerts.length} detection(s) fired`)
      else toast('No detection fired', { icon: '∅' })
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Engine unavailable')
    } finally {
      setBusy(false)
    }
  }

  const summary = result?.rule

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      <div className="card">
        <p className="section-heading">YARA-L rule</p>
        <textarea className="input" rows={16} value={rule} onChange={(e) => setRule(e.target.value)}
          style={{ fontFamily: 'monospace', fontSize: 12.5, resize: 'vertical' }} />
        <p className="section-heading" style={{ marginTop: 14 }}>Sample log lines (one per line)</p>
        <textarea className="input" rows={5} value={lines} onChange={(e) => setLines(e.target.value)}
          style={{ fontFamily: 'monospace', fontSize: 12, resize: 'vertical' }} />
        <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
          <button className="btn-primary" onClick={generateRule} disabled={genBusy}
            style={{ background: 'linear-gradient(135deg,#7c3aed,#2563eb)' }} title="Generate a rule from the first sample line with AI">
            {genBusy ? <Loader2 size={15} className="animate-spin" /> : <Sparkles size={15} />} Generate (AI)
          </button>
          <button className="btn-primary" onClick={run} disabled={busy}>
            {busy ? <Loader2 size={15} className="animate-spin" /> : <ShieldAlert size={15} />} Run detection
          </button>
        </div>
        <p className="page-sub" style={{ marginTop: 10 }}>
          Single-event rules match per line; windowed rules (with a <code>match … over</code> clause)
          aggregate across the lines and fire once the <code>condition</code> count is met.
        </p>
      </div>

      <div className="card">
        <p className="section-heading">Detection result</p>
        {summary && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12, fontSize: 11 }}>
            <span style={{ background: summary.windowed ? 'rgba(192,132,252,.15)' : 'rgba(96,165,250,.15)', color: summary.windowed ? '#c084fc' : '#93c5fd', borderRadius: 4, padding: '2px 8px' }}>
              {summary.windowed ? 'windowed' : 'single-event'}
            </span>
            {summary.windowed && (
              <span style={{ background: 'rgba(148,163,184,.12)', color: '#cbd5e1', borderRadius: 4, padding: '2px 8px', display: 'inline-flex', gap: 4, alignItems: 'center' }}>
                <Clock size={11} /> {summary.threshold}× over {summary.window} by {(summary.group_by || []).join(', ')}
              </span>
            )}
            {(summary.techniques || []).map((t: string) => (
              <span key={t} style={{ background: 'rgba(192,132,252,.15)', color: '#c084fc', borderRadius: 4, padding: '2px 6px' }}>{t}</span>
            ))}
          </div>
        )}
        {!result ? <p className="page-sub" style={{ margin: 0 }}>Run the rule to see which events it fires on.</p> :
          result.error ? (
            <div style={{ color: '#f43f5e', display: 'flex', gap: 8, alignItems: 'center' }}><XCircle size={16} /> {result.error}</div>
          ) : (
            <>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10, color: result.matched ? '#22c55e' : '#94a3b8' }}>
                {result.matched ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                {result.events?.length || 0} events evaluated · {result.alerts?.length || 0} detection(s) fired
              </div>
              <AlertList alerts={result.alerts || []} />
            </>
          )}

        <p className="section-heading" style={{ marginTop: 16 }}>Active YARA-L rules ({yaralRules?.length || 0})</p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {(yaralRules || []).map((r: any) => (
            <div key={r.id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
              <span style={{ background: LEVEL_COLOR(r.level), color: '#0b1020', fontWeight: 700, borderRadius: 4, padding: '1px 6px', fontSize: 11 }}>L{r.level}</span>
              <span style={{ fontFamily: 'monospace', color: '#93c5fd' }}>{r.id}</span>
              {r.format === 'yara-l:windowed' && <span style={{ fontSize: 10, color: '#c084fc' }}>windowed</span>}
              <span style={{ color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Parser authoring guide ────────────────────────────────────────────────────
const GROK_PATTERNS = [
  'IP', 'NUMBER', 'INT', 'PORT', 'WORD', 'NOTSPACE', 'USERNAME', 'HOSTNAME',
  'PATH', 'DATA', 'GREEDYDATA', 'QUOTEDSTRING', 'MAC', 'LOGLEVEL', 'TIME', 'SYSLOGTIMESTAMP',
]
const UDM_PATHS: [string, string[]][] = [
  ['metadata', ['event_type', 'vendor_name', 'product_name', 'log_type', 'description']],
  ['principal (who/source)', ['principal.ip', 'principal.port', 'principal.hostname', 'principal.user.userid', 'principal.process.command_line']],
  ['target (what/dest)', ['target.ip', 'target.port', 'target.hostname', 'target.user.userid', 'target.url', 'target.process.command_line', 'target.file.full_path']],
  ['network', ['network.direction', 'network.ip_protocol', 'network.application_protocol', 'network.http.method', 'network.http.response_code']],
  ['security_result', ['security_result.action', 'security_result.category', 'security_result.severity', 'security_result.summary']],
]
const EVENT_TYPES = ['USER_LOGIN', 'PROCESS_LAUNCH', 'NETWORK_CONNECTION', 'FILE_MODIFICATION', 'STATUS_UPDATE', 'SCAN_HOST', 'GENERIC_EVENT']

function ParserGuide() {
  const mono = { fontFamily: 'monospace', fontSize: 12 } as const
  const chip = (bg: string, color: string) => ({
    fontSize: 11, background: bg, color, borderRadius: 4, padding: '2px 6px', fontFamily: 'monospace',
  } as const)
  return (
    <div className="card" style={{ marginBottom: 16, fontSize: 13, lineHeight: 1.55 }}>
      <p className="section-heading" style={{ marginTop: 0 }}>How to write a parser</p>
      <p className="page-sub" style={{ marginTop: 0 }}>
        A parser turns a raw log into a <b>UDM</b> record. It runs ordered <code>filter</code> steps:
        <b> extract</b> raw values (grok / kv / json), then <b>map</b> them onto UDM fields (<code>set</code>).
        A step's <code>%{'{'}var{'}'}</code> that doesn't resolve is skipped — so partial logs never plant empty fields.
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 12 }}>
        <div>
          <p className="section-heading">Structure</p>
          <pre style={{ background: '#0b1020', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: 12, ...mono, overflowX: 'auto' }}>{`name: myapp              # unique id
log_type: MYAPP          # UDM metadata.log_type
check:                   # gate — when to run
  program: myapp         #   field: value  or  field: /regex/
filter:
  - grok:                # extract with patterns
      source: message    #   field to read (default: message)
      patterns:
        - 'user=%{USERNAME:user} from %{IP:src_ip}'
  - kv: { source: message }        # key=value pairs
  - json: { source: message }      # parse a JSON body
  - set:                 # map vars -> UDM paths
      metadata.event_type: 'USER_LOGIN'
      principal.ip: '%{src_ip}'
      target.user.userid: '%{user}'
  - on: '%{user} == root'          # conditional set
    set: { security_result.severity: 'HIGH' }`}</pre>

          <p className="section-heading" style={{ marginTop: 12 }}>Filter steps</p>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}><tbody>
            {[
              ['grok', 'extract named fields via %{PATTERN:field}; first matching pattern wins'],
              ['kv', 'split key=value pairs (opts: sep, kv_sep)'],
              ['json', 'parse a JSON object; nested keys become dotted vars'],
              ['rename', 'copy one var to another: { newvar: oldvar }'],
              ['set', 'assign UDM paths from literals or %{vars}'],
              ['on + set', 'apply set only when a condition holds (==, !=, =~ /re/)'],
            ].map(([k, v]) => (
              <tr key={k} style={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <td style={{ padding: '5px 8px', ...mono, color: '#93c5fd', width: 90, verticalAlign: 'top' }}>{k}</td>
                <td style={{ padding: '5px 8px', color: '#cbd5e1' }}>{v}</td>
              </tr>
            ))}
          </tbody></table>
        </div>

        <div>
          <p className="section-heading">Grok patterns <span style={{ fontWeight: 400, color: '#94a3b8' }}>· %{'{'}NAME:field{'}'}</span></p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {GROK_PATTERNS.map((p) => <span key={p} style={chip('rgba(96,165,250,.15)', '#93c5fd')}>{p}</span>)}
          </div>

          <p className="section-heading" style={{ marginTop: 14 }}>Common UDM fields</p>
          {UDM_PATHS.map(([group, paths]) => (
            <div key={group} style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 3 }}>{group}</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {paths.map((p) => <span key={p} style={chip('rgba(148,163,184,.12)', '#cbd5e1')}>{p}</span>)}
              </div>
            </div>
          ))}

          <p className="section-heading" style={{ marginTop: 12 }}>event_type values</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {EVENT_TYPES.map((e) => <span key={e} style={chip('rgba(192,132,252,.15)', '#c084fc')}>{e}</span>)}
          </div>

          <p className="page-sub" style={{ marginTop: 14 }}>
            <b>Tips:</b> use <b>Test</b> before saving; a parser named like a built-in saves a custom
            override (delete it to revert); set <code>metadata.event_type</code> so YARA-L rules can
            target the log source.
          </p>
        </div>
      </div>
    </div>
  )
}

// ── Parsers tab (manage CBN parsers: list / view / edit / add / delete) ───────
const NEW_PARSER_TEMPLATE = `name: myapp
log_type: MYAPP
check:
  program: myapp
filter:
  - grok:
      source: message
      patterns:
        - 'user=%{USERNAME:user} from %{IP:src_ip} action=%{WORD:act}'
  - set:
      metadata.event_type: 'USER_LOGIN'
      metadata.vendor_name: 'MyApp'
      principal.ip: '%{src_ip}'
      target.user.userid: '%{user}'
      security_result.action: '%{act}'`

const NEW_KEY = '__new__'

function ParsersTab() {
  const qc = useQueryClient()
  const role = useAuthStore((s) => s.role)
  const isAdmin = role === 'admin'

  const { data: parsers, isLoading } = useQuery({
    queryKey: ['engine-parsers'],
    queryFn: () => api.engineListParsers().then((r) => r.data),
  })

  const [selected, setSelected] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  const [sample, setSample] = useState(
    'Oct 12 18:00:01 web-01 myapp[42]: user=alice from 203.0.113.5 action=login')
  const [test, setTest] = useState<any>(null)
  const [busy, setBusy] = useState(false)
  const [genBusy, setGenBusy] = useState(false)
  const [showGuide, setShowGuide] = useState(false)

  const list: any[] = parsers || []
  const current = selected === NEW_KEY ? null : list.find((p) => p.name === selected)
  const isNew = selected === NEW_KEY
  const isBuiltin = current?.source === 'builtin'

  // Select the first parser once the list loads.
  useEffect(() => {
    if (!selected && list.length) { setSelected(list[0].name); setDraft(list[0].yaml || '') }
  }, [list, selected])

  const pick = (name: string, yaml: string) => { setSelected(name); setDraft(yaml || ''); setTest(null) }
  const startNew = () => { setSelected(NEW_KEY); setDraft(NEW_PARSER_TEMPLATE); setTest(null) }

  const runTest = async () => {
    setBusy(true)
    try {
      const r = await api.engineTestParser(sample, draft)
      setTest(r.data)
      if (r.data.error) toast.error(r.data.error)
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Engine unavailable')
    } finally { setBusy(false) }
  }

  const generate = async () => {
    if (!sample.trim()) { toast.error('Enter a sample log line to generate from'); return }
    setGenBusy(true)
    try {
      const r = await api.engineGenerateParser(sample)
      setSelected(NEW_KEY)          // generated parser is unsaved until Save
      setDraft(r.data.yaml || '')
      setTest(r.data.tested || null)
      toast.success(`Parser generated (${r.data.source}) — review, test, then Save`)
    } catch (e: any) {
      toast.error(e?.response?.data?.detail || 'Generation failed')
    } finally { setGenBusy(false) }
  }

  const saveMut = useMutation({
    mutationFn: () => api.engineSaveParser(draft),
    onSuccess: (r) => {
      if (r.data?.error) { toast.error(r.data.error); return }
      const name = r.data?.saved?.name
      toast.success(`Parser "${name}" saved`)
      qc.invalidateQueries({ queryKey: ['engine-parsers'] })
      qc.invalidateQueries({ queryKey: ['engine-rules'] })
      if (name) setSelected(name)
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Save failed'),
  })

  const deleteMut = useMutation({
    mutationFn: (name: string) => api.engineDeleteParser(name),
    onSuccess: (r) => {
      if (r.data?.error) { toast.error(r.data.error); return }
      toast.success('Parser deleted')
      qc.invalidateQueries({ queryKey: ['engine-parsers'] })
      setSelected(null)
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Delete failed'),
  })

  return (
   <div>
    {/* ── Intro + guide toggle ── */}
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
      <p className="page-sub" style={{ margin: 0, flex: 1 }}>
        CBN parsers normalize raw logs into the <b>UDM</b> — the model YARA-L detections match on.
      </p>
      <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setShowGuide((v) => !v)}>
        {showGuide ? 'Hide guide' : 'How to write a parser'}
      </button>
    </div>
    {showGuide && <ParserGuide />}

    <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 16, alignItems: 'start' }}>
      {/* ── List ── */}
      <div className="card" style={{ padding: 10 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <p className="section-heading" style={{ margin: 0 }}>Parsers ({list.length})</p>
          <button className="btn-primary" style={{ fontSize: 11, padding: '4px 8px' }} onClick={startNew} disabled={!isAdmin}
            title={isAdmin ? 'New parser' : 'Admin only'}>
            <Plus size={12} /> New
          </button>
        </div>
        {isLoading ? <p className="page-sub" style={{ margin: 0 }}>Loading…</p> : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {isNew && (
              <div className="nav-item active" style={{ fontSize: 12 }}>+ new parser (unsaved)</div>
            )}
            {list.map((p) => (
              <button key={p.name} onClick={() => pick(p.name, p.yaml)}
                className={selected === p.name ? 'nav-item active' : 'nav-item'}
                style={{ width: '100%', justifyContent: 'flex-start', fontSize: 12.5 }}>
                <span style={{ flex: 1, textAlign: 'left', fontFamily: 'monospace' }}>{p.name}</span>
                <span style={{
                  fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.05em', padding: '1px 5px', borderRadius: 4,
                  background: p.source === 'custom' ? 'rgba(34,197,94,.15)' : 'rgba(148,163,184,.12)',
                  color: p.source === 'custom' ? '#4ade80' : '#94a3b8',
                }}>{p.source}</span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* ── Editor ── */}
      <div className="card">
        {!selected ? (
          <p className="page-sub" style={{ margin: 0 }}>Select a parser to view or edit, or create a new one.</p>
        ) : (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <p className="section-heading" style={{ margin: 0 }}>
                {isNew ? 'New parser' : current?.name}
                {isBuiltin && <span style={{ fontSize: 11, color: '#94a3b8', fontWeight: 400 }}> · built-in (editing saves a custom override)</span>}
              </p>
              {!isAdmin && <span style={{ fontSize: 11, color: '#94a3b8', display: 'flex', gap: 4, alignItems: 'center' }}><Lock size={12} /> read-only</span>}
            </div>

            <textarea className="input" rows={16} value={draft} onChange={(e) => setDraft(e.target.value)}
              readOnly={!isAdmin}
              style={{ fontFamily: 'monospace', fontSize: 12.5, resize: 'vertical', opacity: isAdmin ? 1 : 0.75 }} />

            <p className="section-heading" style={{ marginTop: 12 }}>Sample log line <span style={{ fontWeight: 400, color: '#94a3b8' }}>· test against it, or generate a parser from it with AI</span></p>
            <input className="input" value={sample} onChange={(e) => setSample(e.target.value)} style={{ fontFamily: 'monospace' }} />

            <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
              <button className="btn-primary" onClick={generate} disabled={genBusy}
                style={{ background: 'linear-gradient(135deg,#7c3aed,#2563eb)' }} title="Generate a parser from the sample with AI">
                {genBusy ? <Loader2 size={15} className="animate-spin" /> : <Sparkles size={15} />} Generate (AI)
              </button>
              <button className="btn-secondary" onClick={runTest} disabled={busy}>
                {busy ? <Loader2 size={15} className="animate-spin" /> : <FlaskConical size={15} />} Test
              </button>
              <button className="btn-primary" onClick={() => saveMut.mutate()} disabled={!isAdmin || saveMut.isPending}>
                {saveMut.isPending ? <Loader2 size={15} className="animate-spin" /> : <Save size={15} />} Save
              </button>
              {!isNew && current?.source === 'custom' && (
                <button className="btn-secondary" style={{ color: '#f87171', marginLeft: 'auto' }}
                  disabled={!isAdmin || deleteMut.isPending}
                  onClick={() => { if (confirm(`Delete parser "${current.name}"?`)) deleteMut.mutate(current.name) }}>
                  <Trash2 size={15} /> Delete
                </button>
              )}
            </div>

            {test && !test.error && (
              <div style={{ marginTop: 14 }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8, color: test.matched ? '#22c55e' : '#94a3b8' }}>
                  {test.matched ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                  {test.matched ? 'Parser matched' : 'No match'}
                  {test.event_type && <span style={{ fontFamily: 'monospace', color: '#93c5fd' }}>· {test.event_type}</span>}
                  {(test.parsers || []).map((d: string) => (
                    <span key={d} style={{ fontSize: 11, background: 'rgba(34,197,94,.15)', color: '#4ade80', borderRadius: 4, padding: '2px 6px' }}>{d}</span>
                  ))}
                </div>
                <FieldsTable fields={test.fields} />
              </div>
            )}
            {test?.error && (
              <div style={{ marginTop: 12, color: '#f43f5e', display: 'flex', gap: 8, alignItems: 'center' }}>
                <XCircle size={16} /> {test.error}
              </div>
            )}
          </>
        )}
      </div>
    </div>
   </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function SocBlitzEngine() {
  const [tab, setTab] = useState<Tab>('normalize')
  const { data: rules } = useQuery({
    queryKey: ['engine-rules'],
    queryFn: () => api.engineRules().then((r) => r.data),
  })

  const tabs: { key: Tab; label: string; icon: any }[] = [
    { key: 'normalize', label: 'Normalize (UDM)', icon: Layers },
    { key: 'parsers', label: 'Parsers', icon: Boxes },
    { key: 'yaral', label: 'YARA-L', icon: ShieldAlert },
    { key: 'test', label: 'Test', icon: Play },
    { key: 'rulegen', label: 'Rule Generation', icon: Wand2 },
  ]

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">SocBlitz Engine</h1>
          <p className="page-sub">
            Normalize logs to UDM and build detections with a Chronicle-style pipeline:
            CBN parsers → Unified Data Model → YARA-L rules.
            {rules ? ` ${rules.length} legacy rules active.` : ''}
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid rgba(255,255,255,0.08)', marginBottom: 16 }}>
        {tabs.map(({ key, label, icon: Icon }) => (
          <button key={key} onClick={() => setTab(key)}
            className={tab === key ? 'btn-secondary' : 'btn-ghost'}
            style={{
              borderRadius: 0, borderBottom: tab === key ? '2px solid #60a5fa' : '2px solid transparent',
              background: 'transparent',
            }}>
            <Icon size={15} /> {label}
          </button>
        ))}
      </div>

      {tab === 'normalize' && <NormalizeTab />}
      {tab === 'parsers' && <ParsersTab />}
      {tab === 'yaral' && <YaraLTab />}
      {tab === 'test' && <TestTab />}
      {tab === 'rulegen' && <RuleGenTab />}
    </div>
  )
}
