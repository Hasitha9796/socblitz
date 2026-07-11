import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw, Search, Filter, CheckCircle } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { api } from '../stores/auth'
import { TimeRangeFilter, rangeToParams, DEFAULT_RANGE, type TimeRange } from '../components/TimeRangeFilter'

const LEVEL_BANDS = [
  { key: 'critical', label: 'Critical', min: 12, color: '#f43f5e' },
  { key: 'high',     label: 'High',     min: 8,  color: '#f97316' },
  { key: 'medium',   label: 'Medium',   min: 4,  color: '#f59e0b' },
  { key: 'low',      label: 'Low',      min: 0,  color: '#67e8f9' },
] as const

function bandFor(level: number) {
  return LEVEL_BANDS.find((b) => level >= b.min) ?? LEVEL_BANDS[LEVEL_BANDS.length - 1]
}

export default function Events() {
  const navigate = useNavigate()
  const [band, setBand] = useState('')
  const [search, setSearch] = useState('')
  const [q, setQ] = useState('')
  const [range, setRange] = useState<TimeRange>(DEFAULT_RANGE)

  // Debounce the query box → server-side Lucene query (query_string on OpenSearch).
  useEffect(() => {
    const t = setTimeout(() => setQ(search.trim()), 400)
    return () => clearTimeout(t)
  }, [search])

  const { data: events, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['events', range, q],
    queryFn: () => api.listEvents({ ...rangeToParams(range), size: 500, ...(q ? { q } : {}) }).then((r) => r.data),
    refetchInterval: 20_000,
    retry: false,
  })

  const queryError = isError ? ((error as any)?.response?.data?.detail || 'Query failed') : null

  const withBand = (events || []).map((e: any) => ({ ...e, _band: bandFor(e.level).key }))

  // `q` is applied server-side; only the level band is filtered client-side here.
  const filtered = withBand.filter((e: any) => !band || e._band === band)

  const counts = LEVEL_BANDS.reduce((acc, b) => {
    acc[b.key] = withBand.filter((e: any) => e._band === b.key).length
    return acc
  }, {} as Record<string, number>)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Events</h1>
          <p className="page-sub">
            Raw Wazuh alert stream — every rule level ({filtered.length} of {events?.length ?? 0})
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

      {/* ── Level quick-filter bar ──────────────────────────────────── */}
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
        {LEVEL_BANDS.map((b) => {
          if (counts[b.key] === 0) return null
          const active = band === b.key
          return (
            <button
              key={b.key}
              onClick={() => setBand(active ? '' : b.key)}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 5,
                padding: '3px 10px', borderRadius: 3, cursor: 'pointer', border: 'none',
                background: active ? b.color + '22' : 'rgba(96,130,182,0.08)',
                outline: active ? `1px solid ${b.color}55` : '1px solid transparent',
                color: active ? b.color : 'var(--text-3)',
                fontSize: 11, fontWeight: active ? 600 : 400,
                transition: 'all 0.12s',
              }}
            >
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: b.color }} />
              {b.label} <span style={{ fontVariantNumeric: 'tabular-nums', opacity: 0.7 }}>{counts[b.key]}</span>
            </button>
          )
        })}

        <div style={{ flex: 1, minWidth: 200 }} />

        <div style={{ position: 'relative' }}>
          <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
          <input
            className="input"
            style={{
              paddingLeft: 30, width: 360, padding: '6px 10px 6px 30px',
              fontFamily: 'JetBrains Mono,monospace', fontSize: 12,
              outline: queryError ? '1px solid #f43f5e88' : undefined,
            }}
            placeholder="Lucene query — e.g. rule.level:>=10 AND agent.name:web-01"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            spellCheck={false}
          />
        </div>
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
                <th style={{ paddingLeft: 12 }}>Level</th>
                <th>Rule / Description</th>
                <th>Agent</th>
                <th>Source IP</th>
                <th>MITRE</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr>
                  <td colSpan={7}>
                    <div className="empty-state">
                      <RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} />
                      <span>Loading events…</span>
                    </div>
                  </td>
                </tr>
              )}

              {!isLoading && filtered.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <div className="empty-state">
                      <CheckCircle size={18} color="#22c55e" />
                      <span>No events matching current filters</span>
                    </div>
                  </td>
                </tr>
              )}

              {filtered.map((e: any) => {
                const color = bandFor(e.level).color
                return (
                  <tr key={e.id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/events/${e.id}`)}>
                    <td style={{ padding: '11px 0 11px 14px', width: 4, boxShadow: `inset 3px 0 0 ${color}` }} />

                    <td style={{ paddingLeft: 12 }}>
                      <span
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: 5,
                          fontSize: 11, fontWeight: 600, color,
                          fontVariantNumeric: 'tabular-nums',
                        }}
                      >
                        <span style={{ width: 5, height: 5, borderRadius: '50%', background: color }} />
                        L{e.level}
                      </span>
                    </td>

                    <td style={{ maxWidth: 320 }}>
                      <p style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {e.description || '(no rule description)'}
                      </p>
                      {e.full_log && (
                        <p style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 1, fontFamily: 'JetBrains Mono,monospace' }}>
                          {e.full_log}
                        </p>
                      )}
                    </td>

                    <td>
                      <p style={{ fontSize: 12 }}>{e.agent_name || '—'}</p>
                      {e.agent_ip && (
                        <p style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-3)', marginTop: 1 }}>{e.agent_ip}</p>
                      )}
                    </td>

                    <td>
                      {e.src_ip
                        ? <span style={{ fontSize: 12, fontFamily: 'JetBrains Mono,monospace', color: '#67e8f9' }}>{e.src_ip}</span>
                        : <span style={{ color: 'var(--text-3)' }}>—</span>}
                    </td>

                    <td>
                      {e.mitre_id ? (
                        <div>
                          <p style={{ fontSize: 12, fontFamily: 'JetBrains Mono,monospace', color: '#60a5fa' }}>{e.mitre_id}</p>
                          {e.mitre_tactic && <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 1 }}>{e.mitre_tactic}</p>}
                        </div>
                      ) : <span style={{ color: 'var(--text-3)' }}>—</span>}
                    </td>

                    <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                      {formatDistanceToNow(new Date(e.timestamp), { addSuffix: true })}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
