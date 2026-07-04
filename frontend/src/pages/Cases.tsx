import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  FolderOpen, Plus, RefreshCw, Search, MessageSquare,
  AlertCircle, CheckCircle2, Clock, Archive, Eye
} from 'lucide-react'
import toast from 'react-hot-toast'
import { formatDistanceToNow } from 'date-fns'
import { api } from '../stores/auth'

const PRIORITY_COLOR: Record<string, string> = {
  critical: '#f43f5e', high: '#f97316', medium: '#f59e0b', low: '#67e8f9',
}
const STATUS_CONFIG: Record<string, { label: string; color: string; icon: any }> = {
  open:        { label: 'Open',        color: '#60a5fa', icon: AlertCircle    },
  in_progress: { label: 'In progress', color: '#fbbf24', icon: Clock         },
  resolved:    { label: 'Resolved',    color: '#22c55e', icon: CheckCircle2  },
  closed:      { label: 'Closed',      color: '#64748b', icon: Archive       },
}

interface NewCaseForm {
  title: string
  description: string
  priority: string
}

export default function Cases() {
  const qc = useQueryClient()
  const [search,     setSearch]    = useState('')
  const [statusFilt, setStatusFilt]= useState('')
  const [creating,   setCreating]  = useState(false)
  const [form, setForm] = useState<NewCaseForm>({ title: '', description: '', priority: 'medium' })

  const { data: cases, isLoading, refetch } = useQuery({
    queryKey: ['cases'],
    queryFn: () => api.listCases({ limit: 200 }).then((r) => r.data),
    refetchInterval: 60_000,
  })

  const createMutation = useMutation({
    mutationFn: (data: any) => api.createCase(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cases'] })
      setCreating(false)
      setForm({ title: '', description: '', priority: 'medium' })
      toast.success('Case created')
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: any) => api.updateCase(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cases'] })
      toast.success('Case updated')
    },
  })

  const filtered = (cases || []).filter((c: any) => {
    const matchSearch = !search || [c.title, c.description, c.assignee].some((f: any) =>
      f?.toLowerCase().includes(search.toLowerCase()))
    const matchStatus = !statusFilt || c.status === statusFilt
    return matchSearch && matchStatus
  })

  const counts = Object.keys(STATUS_CONFIG).reduce((acc, k) => {
    acc[k] = (cases || []).filter((c: any) => c.status === k).length
    return acc
  }, {} as Record<string, number>)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Cases</h1>
          <p className="page-sub">Incident management and investigation tracking</p>
        </div>
        <button className="btn-primary" onClick={() => setCreating(true)}>
          <Plus size={13} /> New case
        </button>
      </div>

      {/* ── Status summary ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
        {Object.entries(STATUS_CONFIG).map(([k, v]) => {
          const Icon = v.icon
          return (
            <button
              key={k}
              className="metric-card"
              style={{
                cursor: 'pointer', textAlign: 'left',
                border: statusFilt === k ? `1px solid ${v.color}44` : undefined,
                outline: statusFilt === k ? `1px solid ${v.color}33` : 'none',
              }}
              onClick={() => setStatusFilt(statusFilt === k ? '' : k)}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <Icon size={12} color={v.color} />
                <p className="metric-label" style={{ color: v.color, textTransform: 'capitalize' }}>{v.label}</p>
              </div>
              <p className="metric-value" style={{ color: v.color }}>{counts[k] ?? 0}</p>
            </button>
          )
        })}
      </div>

      {/* ── Create case panel ── */}
      {creating && (
        <div className="card" style={{ padding: 16 }}>
          <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', marginBottom: 12 }}>New case</p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
            <div style={{ gridColumn: '1 / -1' }}>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Title</label>
              <input
                className="input"
                placeholder="Suspected lateral movement via RDP"
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
              />
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Priority</label>
              <select
                className="select"
                value={form.priority}
                onChange={(e) => setForm({ ...form, priority: e.target.value })}
              >
                {['critical', 'high', 'medium', 'low'].map((p) => (
                  <option key={p} value={p} style={{ textTransform: 'capitalize' }}>{p}</option>
                ))}
              </select>
            </div>
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-3)', display: 'block', marginBottom: 4 }}>Description</label>
              <input
                className="input"
                placeholder="Brief summary of the incident…"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn-primary"
              disabled={!form.title || createMutation.isPending}
              onClick={() => createMutation.mutate(form)}
            >
              {createMutation.isPending ? <RefreshCw size={13} className="animate-spin" /> : <Plus size={13} />}
              Create case
            </button>
            <button className="btn-secondary" onClick={() => setCreating(false)}>Cancel</button>
          </div>
        </div>
      )}

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
            style={{ paddingLeft: 30, width: 240 }}
            placeholder="Search cases…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        {statusFilt && (
          <button
            className="btn-ghost"
            style={{ fontSize: 11 }}
            onClick={() => setStatusFilt('')}
          >
            Clear filter
          </button>
        )}
        <span style={{ fontSize: 11, color: 'var(--text-3)', marginLeft: 'auto' }}>
          {filtered.length} cases
        </span>
      </div>

      {/* ── Cases table ── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Priority</th>
                <th>Case</th>
                <th>Status</th>
                <th>Assignee</th>
                <th>Alerts</th>
                <th>Created</th>
                <th style={{ paddingRight: 16 }}></th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={7}>
                  <div className="empty-state">
                    <RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} />
                    <span>Loading cases…</span>
                  </div>
                </td></tr>
              )}
              {!isLoading && filtered.length === 0 && (
                <tr><td colSpan={7}>
                  <div className="empty-state">
                    <FolderOpen size={18} style={{ color: 'var(--text-3)' }} />
                    <span>No cases found</span>
                  </div>
                </td></tr>
              )}
              {filtered.map((c: any) => {
                const sc = STATUS_CONFIG[c.status] || STATUS_CONFIG.open
                const StatusIcon = sc.icon
                return (
                  <tr key={c.id}>
                    <td>
                      <span
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: 4,
                          fontSize: 11, fontWeight: 600, textTransform: 'capitalize',
                          color: PRIORITY_COLOR[c.priority] || 'var(--text-3)',
                        }}
                      >
                        <span
                          style={{
                            width: 6, height: 6, borderRadius: '50%',
                            background: PRIORITY_COLOR[c.priority] || 'var(--text-3)',
                            boxShadow: c.priority === 'critical' ? `0 0 5px ${PRIORITY_COLOR[c.priority]}` : 'none',
                          }}
                        />
                        {c.priority || 'medium'}
                      </span>
                    </td>

                    <td style={{ maxWidth: 300 }}>
                      <p style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {c.title}
                      </p>
                      {c.description && (
                        <p style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 1 }}>
                          {c.description}
                        </p>
                      )}
                    </td>

                    <td>
                      <span
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: 5,
                          padding: '3px 8px', borderRadius: 3,
                          background: sc.color + '18',
                          color: sc.color, fontSize: 11, fontWeight: 500,
                        }}
                      >
                        <StatusIcon size={11} />
                        {sc.label}
                      </span>
                    </td>

                    <td style={{ fontSize: 12, color: 'var(--text-2)' }}>
                      {c.assignee || <span style={{ color: 'var(--text-3)' }}>Unassigned</span>}
                    </td>

                    <td>
                      {c.alert_count != null ? (
                        <span
                          style={{
                            fontSize: 11, fontWeight: 600, fontVariantNumeric: 'tabular-nums',
                            padding: '2px 8px', borderRadius: 3,
                            background: c.alert_count > 0 ? 'rgba(244,63,94,0.1)' : 'rgba(96,130,182,0.08)',
                            color: c.alert_count > 0 ? '#f43f5e' : 'var(--text-3)',
                          }}
                        >
                          {c.alert_count}
                        </span>
                      ) : '—'}
                    </td>

                    <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                      {c.created_at ? formatDistanceToNow(new Date(c.created_at), { addSuffix: true }) : '—'}
                    </td>

                    <td style={{ paddingRight: 16 }}>
                      <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                        {c.status === 'open' && (
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 11, padding: '3px 10px' }}
                            onClick={() => updateMutation.mutate({ id: c.id, data: { status: 'in_progress' } })}
                          >
                            Start
                          </button>
                        )}
                        {c.status === 'in_progress' && (
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 11, padding: '3px 10px' }}
                            onClick={() => updateMutation.mutate({ id: c.id, data: { status: 'resolved' } })}
                          >
                            Resolve
                          </button>
                        )}
                        <button className="btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }}>
                          <Eye size={12} />
                        </button>
                      </div>
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
