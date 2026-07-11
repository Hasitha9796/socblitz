import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Monitor, RefreshCw, Search, CheckCircle, XCircle,
  AlertTriangle, Clock, WifiOff, Plus, Copy, Terminal, X, Trash2
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
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
  const [showAdd,      setShowAdd] = useState(false)
  const qc = useQueryClient()

  const { data: agents, isLoading, refetch } = useQuery({
    queryKey: ['agents'],
    queryFn: () => api.listAgents({ limit: 500 }).then((r) => r.data),
    refetchInterval: 30_000,
  })

  const removeMutation = useMutation({
    mutationFn: (id: string) => api.deleteAgent(id),
    onSuccess: (res: any) => {
      qc.invalidateQueries({ queryKey: ['agents'] })
      toast.success(`Removed agent ${res?.data?.name || res?.data?.agent_id || ''}`.trim())
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Failed to remove agent'),
  })

  const confirmRemove = (a: any) => {
    if (window.confirm(`Remove agent "${a.name || a.agent_id}" (ID ${a.agent_id}) from the manager?\n\nThis deregisters it — the endpoint will stop reporting until re-enrolled.`)) {
      removeMutation.mutate(a.id)
    }
  }

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
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button className="btn-primary" onClick={() => setShowAdd(true)}>
            <Plus size={14} /> Add agent
          </button>
          <button className="btn-secondary" onClick={() => refetch()}>
            <RefreshCw size={13} className={isLoading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      {showAdd && <AddAgentModal onClose={() => setShowAdd(false)} />}

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
                <th style={{ textAlign: 'right', paddingRight: 16 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={8}>
                  <div className="empty-state">
                    <RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} />
                    <span>Loading agents…</span>
                  </div>
                </td></tr>
              )}
              {!isLoading && filtered.length === 0 && (
                <tr><td colSpan={8}>
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

                    <td style={{ textAlign: 'right', paddingRight: 16 }}>
                      {String(a.agent_id) === '000' ? (
                        <span style={{ fontSize: 11, color: 'var(--text-3)' }}>Manager</span>
                      ) : (
                        <button
                          className="btn-ghost"
                          style={{ fontSize: 11, padding: '4px 10px', color: '#f87171' }}
                          title="Deregister this agent from the manager"
                          disabled={removeMutation.isPending}
                          onClick={() => confirmRemove(a)}
                        >
                          <Trash2 size={12} /> Remove
                        </button>
                      )}
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

/* ── Add agent modal ─────────────────────────────────────────────────────── */
const OS_LABELS: Record<string, string> = { linux: 'Linux', macos: 'macOS', windows: 'Windows' }

function AddAgentModal({ onClose }: { onClose: () => void }) {
  const [os, setOs] = useState<'linux' | 'macos' | 'windows'>('linux')

  const { data, isLoading } = useQuery({
    queryKey: ['agent-deploy-command'],
    queryFn: () => api.agentDeployCommand().then((r) => r.data),
  })

  const command: string = data?.[os] || ''

  const copy = (text: string) => {
    navigator.clipboard.writeText(text)
      .then(() => toast.success('Copied to clipboard'))
      .catch(() => toast.error('Copy failed — select and copy manually'))
  }

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, zIndex: 100,
        background: 'rgba(0,0,0,0.55)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="card"
        style={{ width: 640, maxWidth: '100%', maxHeight: '90vh', overflow: 'auto', padding: 0 }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 20px', borderBottom: '1px solid var(--line)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Terminal size={16} color="#60a5fa" />
            <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)' }}>Add an agent</span>
          </div>
          <button className="btn-ghost" style={{ padding: 4 }} onClick={onClose}><X size={16} /></button>
        </div>

        <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <p style={{ fontSize: 12, color: 'var(--text-3)' }}>
            Run the command below <b>on the endpoint you want to onboard</b> — with
            sudo (Linux/macOS) or in an elevated PowerShell (Windows). It installs the
            SocBlitz agent, enrolls it with this server, and starts reporting. The new
            agent appears in this list within a minute.
            {os === 'macos' && (
              <> <span style={{ color: 'var(--text-2)' }}>macOS installs the SIEM agent only
              (forensics component is Linux/Windows).</span></>
            )}
          </p>

          {/* OS selector */}
          <div style={{ display: 'flex', gap: 4 }}>
            {(['linux', 'macos', 'windows'] as const).map((k) => (
              <button
                key={k}
                onClick={() => setOs(k)}
                style={{
                  padding: '5px 14px', borderRadius: 4, cursor: 'pointer', border: 'none',
                  fontSize: 12, fontWeight: os === k ? 600 : 400,
                  background: os === k ? 'rgba(37,99,235,0.2)' : 'rgba(96,130,182,0.08)',
                  color: os === k ? '#60a5fa' : 'var(--text-3)',
                  outline: os === k ? '1px solid rgba(37,99,235,0.35)' : '1px solid transparent',
                }}
              >
                {OS_LABELS[k]}
              </button>
            ))}
          </div>

          {/* Command block */}
          {isLoading ? (
            <div className="empty-state"><RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} /><span>Loading…</span></div>
          ) : !data?.configured ? (
            <div style={{
              fontSize: 12, color: '#fbbf24', padding: '10px 12px',
              background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.2)', borderRadius: 6,
            }}>
              {data?.hint || 'Agent enrollment is not configured. Set AGENT_ENROLL_KEY in .env and restart the backend.'}
            </div>
          ) : (
            <div style={{ position: 'relative' }}>
              <pre style={{
                margin: 0, padding: '14px 44px 14px 14px', background: 'var(--raise)',
                border: '1px solid var(--line)', borderRadius: 6, overflowX: 'auto',
                fontFamily: 'JetBrains Mono,monospace', fontSize: 12, color: 'var(--text-1)',
                whiteSpace: 'pre-wrap', wordBreak: 'break-all',
              }}>{command}</pre>
              <button
                className="btn-ghost"
                style={{ position: 'absolute', top: 8, right: 8, padding: 5 }}
                title="Copy command"
                onClick={() => copy(command)}
              >
                <Copy size={14} />
              </button>
            </div>
          )}

          {data?.configured && (
            <p style={{ fontSize: 11, color: 'var(--text-3)' }}>
              The endpoint must be able to reach this server on the enrollment port.
              Firewalled hosts need outbound access to it. After install, use
              <b> Refresh</b> to see the agent register.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
