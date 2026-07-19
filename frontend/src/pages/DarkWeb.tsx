import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Radar, Search, RefreshCw, Globe, Mail, Tag, Plus, Trash2,
  AlertTriangle, ShieldAlert, Database, Eye,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../stores/auth'

type EntityType = 'domain' | 'email' | 'keyword'

const ENTITY_META: Record<EntityType, { icon: any; label: string; placeholder: string }> = {
  domain:  { icon: Globe, label: 'Company domain', placeholder: 'acme.com' },
  email:   { icon: Mail,  label: 'Email address',  placeholder: 'ceo@acme.com' },
  keyword: { icon: Tag,   label: 'Brand / keyword', placeholder: 'Acme Corp' },
}

const SEV_COLOR: Record<string, string> = {
  critical: '#f43f5e', high: '#f97316', medium: '#eab308', low: '#38bdf8', info: '#94a3b8',
}

const STATUS_LABEL: Record<string, string> = {
  new: 'New', investigating: 'Investigating', resolved: 'Resolved', false_positive: 'False positive',
}

// Branded provider names — never leak the raw upstream product identity in the UI.
const SOURCE_LABEL: Record<string, string> = {
  hibp: 'Breach Index', intelx: 'Darkweb Search', dehashed: 'Credential Leaks', leakcheck: 'Leak Database',
}
const sourceLabel = (s: string) => SOURCE_LABEL[s] || s

export default function DarkWeb() {
  const qc = useQueryClient()
  const [entityType, setEntityType] = useState<EntityType>('domain')
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  // Add-asset form
  const [addType, setAddType] = useState<EntityType>('domain')
  const [addValue, setAddValue] = useState('')

  const { data: stats } = useQuery({
    queryKey: ['darkweb-stats'],
    queryFn: () => api.darkwebStats().then((r) => r.data),
    refetchInterval: 60_000,
  })
  const { data: assets = [] } = useQuery({
    queryKey: ['darkweb-assets'],
    queryFn: () => api.darkwebAssets().then((r) => r.data),
    refetchInterval: 30_000,
  })
  const { data: findings = [] } = useQuery({
    queryKey: ['darkweb-findings'],
    queryFn: () => api.darkwebFindings({ limit: 100 }).then((r) => r.data),
    refetchInterval: 30_000,
  })

  async function handleSearch(e: React.FormEvent) {
    e.preventDefault()
    if (!query.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const { data } = await api.darkwebSearch(query.trim(), entityType)
      setResult(data)
    } catch {
      toast.error('Search failed — check dark web provider configuration')
    } finally {
      setLoading(false)
    }
  }

  async function handleAddAsset(e: React.FormEvent) {
    e.preventDefault()
    if (!addValue.trim()) return
    try {
      await api.darkwebCreateAsset({ value: addValue.trim(), entity_type: addType })
      toast.success('Now monitoring — first scan queued')
      setAddValue('')
      qc.invalidateQueries({ queryKey: ['darkweb-assets'] })
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Could not add asset')
    }
  }

  async function handleScan(id: string) {
    try {
      await api.darkwebScanAsset(id)
      toast.success('Rescan queued')
    } catch {
      toast.error('Could not queue scan')
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Stop monitoring this asset and delete its findings?')) return
    try {
      await api.darkwebDeleteAsset(id)
      qc.invalidateQueries({ queryKey: ['darkweb-assets'] })
      qc.invalidateQueries({ queryKey: ['darkweb-findings'] })
    } catch {
      toast.error('Could not delete asset')
    }
  }

  async function handleStatus(id: string, status: string) {
    try {
      await api.darkwebUpdateFinding(id, status)
      qc.invalidateQueries({ queryKey: ['darkweb-findings'] })
      qc.invalidateQueries({ queryKey: ['darkweb-stats'] })
    } catch {
      toast.error('Could not update finding')
    }
  }

  const meta = ENTITY_META[entityType]
  const Icon = meta.icon
  const bySev = stats?.by_severity || {}

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Dark Web Monitoring</h1>
          <p className="page-sub">Leaked accounts &amp; enterprise exposure across breach and dark web sources</p>
        </div>
      </div>

      {/* ── Stat tiles ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12 }}>
        <StatTile icon={Radar}       label="Monitored assets" value={stats?.monitored_assets ?? 0} color="#60a5fa" />
        <StatTile icon={Database}    label="Total exposures"  value={stats?.total_findings ?? 0}   color="#c084fc" />
        <StatTile icon={ShieldAlert} label="Critical / high"  value={(bySev.critical ?? 0) + (bySev.high ?? 0)} color="#f43f5e" />
        <StatTile icon={Eye}         label="New / untriaged"  value={stats?.by_status?.new ?? 0}   color="#f97316" />
      </div>

      {/* ── On-demand search ── */}
      <div className="card" style={{ padding: 20 }}>
        <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Dark web search
        </p>

        <div style={{ display: 'flex', gap: 4, marginBottom: 12, flexWrap: 'wrap' }}>
          {(Object.entries(ENTITY_META) as [EntityType, any][]).map(([type, m]) => {
            const TypeIcon = m.icon
            const active = entityType === type
            return (
              <button
                key={type}
                onClick={() => { setEntityType(type); setResult(null) }}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 5,
                  padding: '5px 12px', borderRadius: 4, cursor: 'pointer',
                  border: 'none', fontSize: 12, fontWeight: active ? 600 : 400,
                  background: active ? 'rgba(37,99,235,0.2)' : 'rgba(96,130,182,0.08)',
                  color: active ? '#60a5fa' : 'var(--text-3)',
                  outline: active ? '1px solid rgba(37,99,235,0.35)' : '1px solid transparent',
                  transition: 'all 0.12s',
                }}
              >
                <TypeIcon size={12} />
                {m.label}
              </button>
            )
          })}
        </div>

        <form onSubmit={handleSearch} style={{ display: 'flex', gap: 8 }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Icon size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)', pointerEvents: 'none' }} />
            <input
              className="input"
              style={{ paddingLeft: 36 }}
              placeholder={meta.placeholder}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              required
            />
          </div>
          <button type="submit" className="btn-primary" disabled={loading}>
            {loading
              ? <><RefreshCw size={13} className="animate-spin" /> Searching…</>
              : <><Search size={13} /> Search</>}
          </button>
        </form>

        {result && <SearchResults result={result} />}
      </div>

      {/* ── Monitored assets ── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--line)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Monitored assets
          </p>
          <form onSubmit={handleAddAsset} style={{ display: 'flex', gap: 6 }}>
            <select
              className="input"
              style={{ width: 130, padding: '5px 8px', fontSize: 12 }}
              value={addType}
              onChange={(e) => setAddType(e.target.value as EntityType)}
            >
              <option value="domain">Domain</option>
              <option value="email">Email</option>
              <option value="keyword">Keyword</option>
            </select>
            <input
              className="input"
              style={{ width: 200, padding: '5px 10px', fontSize: 12 }}
              placeholder={ENTITY_META[addType].placeholder}
              value={addValue}
              onChange={(e) => setAddValue(e.target.value)}
            />
            <button type="submit" className="btn-primary" style={{ padding: '5px 12px', fontSize: 12 }}>
              <Plus size={12} /> Monitor
            </button>
          </form>
        </div>

        {assets.length === 0 ? (
          <p style={{ padding: 20, fontSize: 13, color: 'var(--text-3)', textAlign: 'center' }}>
            No monitored assets yet. Add a domain, email, or brand keyword to track exposures continuously.
          </p>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th style={{ width: 100 }}>Type</th>
                  <th style={{ width: 90 }}>Exposures</th>
                  <th style={{ width: 80 }}>New</th>
                  <th style={{ width: 160 }}>Last scanned</th>
                  <th style={{ width: 110 }}></th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a: any) => (
                  <tr key={a.id}>
                    <td style={{ fontSize: 13, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-1)' }}>{a.value}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-3)', textTransform: 'capitalize' }}>{a.entity_type}</td>
                    <td style={{ fontSize: 13, color: 'var(--text-2)', fontVariantNumeric: 'tabular-nums' }}>{a.finding_count}</td>
                    <td>
                      {a.new_count > 0
                        ? <span style={{ fontSize: 11, fontWeight: 600, padding: '2px 7px', borderRadius: 3, background: 'rgba(249,115,22,0.14)', color: '#f97316' }}>{a.new_count}</span>
                        : <span style={{ fontSize: 12, color: 'var(--text-3)' }}>—</span>}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)' }}>
                      {a.last_scanned_at ? new Date(a.last_scanned_at).toLocaleString() : 'Pending first scan…'}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
                        <button onClick={() => handleScan(a.id)} title="Rescan now" className="icon-btn" style={iconBtn}>
                          <RefreshCw size={13} />
                        </button>
                        <button onClick={() => handleDelete(a.id)} title="Stop monitoring" className="icon-btn" style={{ ...iconBtn, color: '#f43f5e' }}>
                          <Trash2 size={13} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Findings feed ── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--line)' }}>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Exposure findings
          </p>
        </div>
        {findings.length === 0 ? (
          <p style={{ padding: 20, fontSize: 13, color: 'var(--text-3)', textAlign: 'center' }}>
            No exposures recorded yet. Findings from monitored-asset scans appear here.
          </p>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 90 }}>Severity</th>
                  <th>Exposure</th>
                  <th style={{ width: 130 }}>Source</th>
                  <th style={{ width: 150 }}>Asset</th>
                  <th style={{ width: 110 }}>Leak date</th>
                  <th style={{ width: 150 }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f: any) => (
                  <tr key={f.id}>
                    <td><SevBadge severity={f.severity} /></td>
                    <td>
                      <p style={{ fontSize: 13, color: 'var(--text-1)', fontWeight: 500 }}>{f.title}</p>
                      {f.exposed_data?.length > 0 && (
                        <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>{f.exposed_data.join(' · ')}</p>
                      )}
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{sourceLabel(f.source)}</td>
                    <td style={{ fontSize: 12, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-3)' }}>{f.entity_value}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{f.leak_date || '—'}</td>
                    <td>
                      <select
                        value={f.status}
                        onChange={(e) => handleStatus(f.id, e.target.value)}
                        className="input"
                        style={{ padding: '4px 8px', fontSize: 12 }}
                      >
                        {Object.entries(STATUS_LABEL).map(([v, l]) => (
                          <option key={v} value={v}>{l}</option>
                        ))}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

function SearchResults({ result }: { result: any }) {
  const findings: any[] = result.findings || []
  const skipped: string[] = result.skipped || []
  const errors: Record<string, string> = result.errors || {}

  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <span style={{ fontSize: 14, fontWeight: 700, color: findings.length ? '#f97316' : '#22c55e' }}>
          {findings.length} exposure{findings.length === 1 ? '' : 's'} found
        </span>
        <span style={{ fontSize: 11, color: 'var(--text-3)' }}>
          across {result.sources?.length || 0} source{result.sources?.length === 1 ? '' : 's'}
          {result.summary?.latest_leak ? ` · latest ${result.summary.latest_leak}` : ''}
        </span>
      </div>

      {findings.length === 0 && (
        <p style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 10 }}>
          No exposures surfaced by the configured sources. This is not proof of safety — coverage depends on which providers are enabled.
        </p>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {findings.map((f, i) => (
          <div
            key={i}
            style={{
              padding: 12, borderRadius: 8, background: 'var(--raise)',
              border: `1px solid ${(SEV_COLOR[f.severity] || 'var(--line)')}30`,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <SevBadge severity={f.severity} />
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>{f.title}</span>
              <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-3)' }}>{sourceLabel(f.source)}</span>
            </div>
            {f.description && (
              <p style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: f.exposed_data?.length ? 6 : 0 }}>{f.description}</p>
            )}
            {f.exposed_data?.length > 0 && (
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                {f.exposed_data.map((d: string) => (
                  <span key={d} style={{ fontSize: 11, padding: '2px 8px', borderRadius: 3, background: 'rgba(244,63,94,0.1)', border: '1px solid rgba(244,63,94,0.15)', color: '#f87171' }}>{d}</span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {(skipped.length > 0 || Object.keys(errors).length > 0) && (
        <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 4 }}>
          {skipped.length > 0 && (
            <p style={{ fontSize: 11, color: 'var(--text-3)' }}>
              <AlertTriangle size={11} style={{ display: 'inline', verticalAlign: 'middle', marginRight: 4 }} />
              Not checked: {skipped.join(', ')}
            </p>
          )}
          {Object.entries(errors).map(([src, msg]) => (
            <p key={src} style={{ fontSize: 11, color: '#f87171' }}>{sourceLabel(src)}: {msg}</p>
          ))}
        </div>
      )}
    </div>
  )
}

function SevBadge({ severity }: { severity: string }) {
  const color = SEV_COLOR[severity] || '#94a3b8'
  return (
    <span style={{
      fontSize: 11, fontWeight: 600, textTransform: 'capitalize',
      padding: '2px 8px', borderRadius: 3,
      background: `${color}1f`, color, border: `1px solid ${color}40`,
    }}>
      {severity}
    </span>
  )
}

function StatTile({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  return (
    <div className="card" style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
      <div style={{ width: 36, height: 36, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', background: `${color}1a` }}>
        <Icon size={18} color={color} />
      </div>
      <div>
        <p style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-1)', lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{value}</p>
        <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 3, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</p>
      </div>
    </div>
  )
}

const iconBtn: React.CSSProperties = {
  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
  width: 28, height: 28, borderRadius: 4, cursor: 'pointer',
  background: 'rgba(96,130,182,0.08)', border: 'none', color: 'var(--text-2)',
}
