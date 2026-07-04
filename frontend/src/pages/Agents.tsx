import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Monitor, RefreshCw, Search, CheckCircle, XCircle,
  AlertTriangle, Clock, WifiOff
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { api } from '../stores/auth'

const STATUS_CONFIG: Record<string, { label: string; icon: any; color: string; bg: string }> = {
  active:       { label: 'Active',       icon: CheckCircle,   color: '#22c55e', bg: 'rgba(34,197,94,0.1)'   },
  disconnected: { label: 'Disconnected', icon: WifiOff,       color: '#f43f5e', bg: 'rgba(244,63,94,0.1)'   },
  never:        { label: 'Never seen',   icon: AlertTriangle, color: '#f59e0b', bg: 'rgba(245,158,11,0.1)'  },
  pending:      { label: 'Pending',      icon: Clock,         color: '#94a3b8', bg: 'rgba(148,163,184,0.1)' },
}

export default function Agents() {
  const [search,       setSearch]  = useState('')
  const [statusFilter, setStatus]  = useState('')

  const { data: agents, isLoading, refetch } = useQuery({
    queryKey: ['agents'],
    queryFn: () => api.listAgents({ limit: 500 }).then((r) => r.data),
    refetchInterval: 30_000,
  })

  const filtered = (agents || []).filter((a: any) => {
    const matchSearch = !search ||
      [a.name, a.ip, a.os, a.hostname].some((f: any) => f?.toLowerCase().includes(search.toLowerCase()))
    const matchStatus = !statusFilter || a.status === statusFilter
    return matchSearch && matchStatus
  })

  const counts = {
    active:       (agents || []).filter((a: any) => a.status === 'active').length,
    disconnected: (agents || []).filter((a: any) => a.status === 'disconnected').length,
    total: agents?.length ?? 0,
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Agents</h1>
          <p className="page-sub">Endpoint sensors and monitoring status</p>
        </div>
        <button className="btn-secondary" onClick={() => refetch()}>
          <RefreshCw size={13} className={isLoading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* ── Summary tiles ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
        {[
          { label: 'Total agents',  value: counts.total,        color: '#60a5fa' },
          { label: 'Active',        value: counts.active,       color: '#22c55e' },
          { label: 'Disconnected',  value: counts.disconnected, color: '#f43f5e' },
        ].map(({ label, value, color }) => (
          <div key={label} className="metric-card">
            <p className="metric-label">{label}</p>
            <p className="metric-value" style={{ color }}>{value}</p>
          </div>
        ))}
      </div>

      {/* ── Filters ── */}
      <div
        style={{
          display: 'flex', gap: 8, padding: '10px 14px',
          background: 'var(--lift)', border: '1px solid var(--line)',
          borderRadius: 8, flexWrap: 'wrap', alignItems: 'center',
        }}
      >
        <div style={{ position: 'relative' }}>
          <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)', pointerEvents: 'none' }} />
          <input
            className="input"
            style={{ paddingLeft: 30, width: 220 }}
            placeholder="Search agents, IPs, hostnames…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          className="select"
          value={statusFilter}
          onChange={(e) => setStatus(e.target.value)}
          style={{ width: 160 }}
        >
          <option value="">All statuses</option>
          {Object.entries(STATUS_CONFIG).map(([k, v]) => (
            <option key={k} value={k}>{v.label}</option>
          ))}
        </select>
        <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>
          {filtered.length} of {counts.total} agents
        </span>
      </div>

      {/* ── Table ── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Status</th>
                <th>Agent name</th>
                <th>IP address</th>
                <th>OS</th>
                <th>Version</th>
                <th>Last seen</th>
                <th>Group</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={7}>
                  <div className="empty-state">
                    <RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} />
                    <span>Loading agents…</span>
                  </div>
                </td></tr>
              )}
              {!isLoading && filtered.length === 0 && (
                <tr><td colSpan={7}>
                  <div className="empty-state">
                    <Monitor size={18} style={{ color: 'var(--text-3)' }} />
                    <span>No agents found</span>
                  </div>
                </td></tr>
              )}
              {filtered.map((a: any) => {
                const sc = STATUS_CONFIG[a.status] || STATUS_CONFIG.pending
                const Icon = sc.icon
                return (
                  <tr key={a.id}>
                    <td>
                      <span
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: 5,
                          padding: '3px 8px', borderRadius: 3,
                          background: sc.bg, color: sc.color,
                          fontSize: 11, fontWeight: 500,
                        }}
                      >
                        <Icon size={11} /> {sc.label}
                      </span>
                    </td>

                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div
                          style={{
                            width: 28, height: 28, borderRadius: 6, flexShrink: 0,
                            background: 'rgba(96,130,182,0.1)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                          }}
                        >
                          <Monitor size={13} color="#60a5fa" />
                        </div>
                        <div>
                          <p style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-1)' }}>{a.name || a.hostname || a.id}</p>
                          {a.hostname && a.name !== a.hostname && (
                            <p style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: 'JetBrains Mono,monospace' }}>{a.hostname}</p>
                          )}
                        </div>
                      </div>
                    </td>

                    <td>
                      <span style={{ fontSize: 12, fontFamily: 'JetBrains Mono,monospace', color: '#67e8f9' }}>
                        {a.ip || a.ip_address || '—'}
                      </span>
                    </td>

                    <td>
                      <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{a.os || '—'}</span>
                    </td>

                    <td>
                      <span style={{ fontSize: 12, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-3)' }}>
                        {a.version || '—'}
                      </span>
                    </td>

                    <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                      {a.last_seen
                        ? formatDistanceToNow(new Date(a.last_seen), { addSuffix: true })
                        : '—'}
                    </td>

                    <td>
                      {a.group ? (
                        <span
                          style={{
                            fontSize: 11, padding: '2px 7px', borderRadius: 3,
                            background: 'rgba(96,130,182,0.08)',
                            border: '1px solid rgba(96,130,182,0.12)',
                            color: 'var(--text-2)',
                          }}
                        >
                          {a.group}
                        </span>
                      ) : <span style={{ color: 'var(--text-3)' }}>—</span>}
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
