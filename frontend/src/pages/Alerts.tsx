import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { RefreshCw, Search, Filter, CheckCircle, AlertOctagon } from 'lucide-react'
import toast from 'react-hot-toast'
import { formatDistanceToNow } from 'date-fns'
import { api } from '../stores/auth'
import { TimeRangeFilter, rangeToParams, DEFAULT_RANGE, type TimeRange } from '../components/TimeRangeFilter'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
const STATUSES   = ['new', 'in_triage', 'escalated', 'resolved', 'false_positive'] as const

const STATUS_BADGE: Record<string, string> = {
  new:            'badge-critical',
  in_triage:      'badge-medium',
  escalated:      'badge-high',
  resolved:       'badge-success',
  false_positive: 'badge-muted',
}
const SEV_LABEL: Record<string, string> = {
  critical: '#f43f5e', high: '#f97316', medium: '#f59e0b', low: '#67e8f9', info: '#64748b',
}

export default function Alerts() {
  const navigate = useNavigate()
  const [sev,    setSev]    = useState('')
  const [status, setStatus] = useState('')
  const [search, setSearch] = useState('')
  const [q,      setQ]      = useState('')
  const [range,  setRange]  = useState<TimeRange>(DEFAULT_RANGE)
  const qc = useQueryClient()

  // Debounce the query box → server-side field:value filter.
  useEffect(() => {
    const t = setTimeout(() => setQ(search.trim()), 400)
    return () => clearTimeout(t)
  }, [search])

  const { data: alerts, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['alerts', sev, status, range, q],
    queryFn: () => api.listAlerts({
      ...(sev    ? { severity: sev } : {}),
      ...(status ? { status }        : {}),
      ...(q      ? { q }             : {}),
      ...rangeToParams(range),
      limit: 200,
    }).then((r) => r.data),
    refetchInterval: 20_000,
    retry: false,
  })

  const queryError = isError ? ((error as any)?.response?.data?.detail || 'Query failed') : null

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => api.updateAlert(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      toast.success('Alert updated')
    },
  })

  // `q` is applied server-side; the returned rows are already filtered.
  const filtered = alerts || []

  const counts = SEVERITIES.reduce((acc, s) => {
    acc[s] = (alerts || []).filter((a: any) => a.severity === s).length
    return acc
  }, {} as Record<string, number>)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Alerts</h1>
          <p className="page-sub">
            {filtered.length} of {alerts?.length ?? 0} alerts
            {sev || status ? ' (filtered)' : ''}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <TimeRangeFilter value={range} onChange={setRange} />
          <button onClick={() => refetch()} className="btn-secondary">
            <RefreshCw size={13} className={isLoading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {/* ── Severity quick-filter bar ────────────────────────────────── */}
      <div
        style={{
          display: 'flex', gap: 6, padding: '10px 14px',
          background: 'var(--lift)', border: '1px solid var(--line)', borderRadius: 8,
          flexWrap: 'wrap', alignItems: 'center',
        }}
      >
        <span style={{ fontSize: 11, color: 'var(--text-3)', marginRight: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
          <Filter size={12} /> Filter
        </span>
        {SEVERITIES.map((s) => {
          if (counts[s] === 0) return null
          const active = sev === s
          return (
            <button
              key={s}
              onClick={() => setSev(active ? '' : s)}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 5,
                padding: '3px 10px', borderRadius: 3, cursor: 'pointer', border: 'none',
                background: active ? SEV_LABEL[s] + '22' : 'rgba(96,130,182,0.08)',
                outline: active ? `1px solid ${SEV_LABEL[s]}55` : '1px solid transparent',
                color: active ? SEV_LABEL[s] : 'var(--text-3)',
                fontSize: 11, fontWeight: active ? 600 : 400,
                transition: 'all 0.12s',
              }}
            >
              <span
                style={{
                  width: 5, height: 5, borderRadius: '50%',
                  background: SEV_LABEL[s],
                  boxShadow: s === 'critical' ? `0 0 5px ${SEV_LABEL[s]}` : 'none',
                }}
              />
              {s} <span style={{ fontVariantNumeric: 'tabular-nums', opacity: 0.7 }}>{counts[s]}</span>
            </button>
          )
        })}

        <div style={{ flex: 1, minWidth: 200 }} />

        {/* Query filter (field:value mini-DSL) */}
        <div style={{ position: 'relative' }}>
          <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
          <input
            className="input"
            style={{
              paddingLeft: 30, width: 320, padding: '6px 10px 6px 30px',
              fontFamily: 'JetBrains Mono,monospace', fontSize: 12,
              outline: queryError ? '1px solid #f43f5e88' : undefined,
            }}
            placeholder="Filter — e.g. agent:web-01 level:>=10"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            spellCheck={false}
          />
        </div>

        {/* Status filter */}
        <select
          className="select"
          style={{ width: 150, padding: '6px 28px 6px 10px' }}
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          <option value="">All statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
          ))}
        </select>
      </div>

      {queryError && (
        <div style={{
          fontSize: 12, color: '#f87171', padding: '8px 12px',
          background: 'rgba(244,63,94,0.08)', border: '1px solid rgba(244,63,94,0.2)',
          borderRadius: 6, fontFamily: 'JetBrains Mono,monospace',
        }}>
          {queryError}
        </div>
      )}

      {/* ── Table ───────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 4, padding: '10px 0 10px 14px' }}></th>
                <th style={{ paddingLeft: 12 }}>Severity</th>
                <th>Rule / Description</th>
                <th>Agent</th>
                <th>Source IP</th>
                <th>MITRE</th>
                <th>Status</th>
                <th>Time</th>
                <th style={{ paddingRight: 16 }}></th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr>
                  <td colSpan={9}>
                    <div className="empty-state">
                      <RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} />
                      <span>Loading alerts…</span>
                    </div>
                  </td>
                </tr>
              )}

              {!isLoading && filtered.length === 0 && (
                <tr>
                  <td colSpan={9}>
                    <div className="empty-state">
                      <CheckCircle size={18} color="#22c55e" />
                      <span>No alerts matching current filters</span>
                    </div>
                  </td>
                </tr>
              )}

              {filtered.map((a: any) => (
                <tr key={a.id} className={`sev-${a.severity}`} style={{ cursor: 'pointer' }} onClick={() => navigate(`/alerts/${a.id}`)}>
                  {/* Invisible first cell so box-shadow stripe shows */}
                  <td style={{ padding: '11px 0 11px 14px', width: 4 }} />

                  <td style={{ paddingLeft: 12 }}>
                    <span className={`badge-${a.severity}`} style={{ textTransform: 'capitalize' }}>
                      {a.severity}
                    </span>
                  </td>

                  <td style={{ maxWidth: 280 }}>
                    <p style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.rule_name || '(no rule name)'}
                    </p>
                    {a.description && (
                      <p style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 1 }}>
                        {a.description}
                      </p>
                    )}
                  </td>

                  <td>
                    <p style={{ fontSize: 12 }}>{a.agent_name || '—'}</p>
                    {a.agent_ip && (
                      <p style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-3)', marginTop: 1 }}>{a.agent_ip}</p>
                    )}
                  </td>

                  <td>
                    {a.src_ip
                      ? <span style={{ fontSize: 12, fontFamily: 'JetBrains Mono,monospace', color: '#67e8f9' }}>{a.src_ip}</span>
                      : <span style={{ color: 'var(--text-3)' }}>—</span>}
                  </td>

                  <td>
                    {a.mitre_id ? (
                      <div>
                        <p style={{ fontSize: 12, fontFamily: 'JetBrains Mono,monospace', color: '#60a5fa' }}>{a.mitre_id}</p>
                        {a.mitre_tactic && <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 1 }}>{a.mitre_tactic}</p>}
                      </div>
                    ) : <span style={{ color: 'var(--text-3)' }}>—</span>}
                  </td>

                  <td>
                    <span className={STATUS_BADGE[a.status] || 'badge-muted'} style={{ textTransform: 'capitalize' }}>
                      {a.status?.replace(/_/g, ' ')}
                    </span>
                  </td>

                  <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                    {formatDistanceToNow(new Date(a.alert_time), { addSuffix: true })}
                  </td>

                  <td style={{ paddingRight: 16 }}>
                    <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                      {a.status === 'new' && (
                        <button
                          className="btn-secondary"
                          style={{ fontSize: 11, padding: '3px 10px' }}
                          onClick={(e) => { e.stopPropagation(); updateMutation.mutate({ id: a.id, data: { status: 'in_triage' } }) }}
                        >
                          Triage
                        </button>
                      )}
                      {a.status !== 'resolved' && a.status !== 'false_positive' && (
                        <button
                          className="btn-ghost"
                          style={{ fontSize: 11, padding: '3px 10px' }}
                          onClick={(e) => { e.stopPropagation(); updateMutation.mutate({ id: a.id, data: { status: 'resolved' } }) }}
                        >
                          Resolve
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
