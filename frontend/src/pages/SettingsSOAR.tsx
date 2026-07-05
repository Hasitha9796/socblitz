import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Workflow, Play, Clock, Pencil, Trash2,
  ChevronRight, Zap, Plus
} from 'lucide-react'
import toast from 'react-hot-toast'
import { formatDistanceToNow } from 'date-fns'
import { api } from '../stores/auth'

export function SOAR() { return <SettingsSOAR /> }
export function Settings() { return <SettingsSOAR /> }

function describeTrigger(wf: any): string {
  if (wf.trigger_type === 'alert') {
    return `Alert: severity>=${wf.trigger_config?.severity ?? 'critical'}`
  }
  if (wf.trigger_type === 'schedule') return 'Schedule'
  if (wf.trigger_type === 'webhook') return 'Webhook'
  return 'Manual'
}

export function SettingsSOAR() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState<string | null>(null)

  const { data: workflows, isLoading } = useQuery({
    queryKey: ['workflows'],
    queryFn: () => api.listWorkflows().then((r) => r.data),
    refetchInterval: 30_000,
  })

  const runMutation = useMutation({
    mutationFn: (id: string) => api.runWorkflow(id),
    onSuccess: () => {
      toast.success('Workflow run queued')
      qc.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: () => toast.error('Failed to queue workflow run'),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) =>
      api.updateWorkflow(id, { is_active }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: () => toast.error('Failed to update workflow'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.deleteWorkflow(id),
    onSuccess: () => {
      toast.success('Workflow deleted')
      qc.invalidateQueries({ queryKey: ['workflows'] })
    },
    onError: () => toast.error('Failed to delete workflow'),
  })

  const list = workflows || []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">SOAR</h1>
          <p className="page-sub">Security orchestration, automation, and response workflows</p>
        </div>
        <button className="btn-primary" onClick={() => navigate('/soar/new')}>
          <Plus size={13} /> New workflow
        </button>
      </div>

      {/* ── Stats row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
        {[
          { label: 'Total workflows',  value: list.length, color: '#60a5fa' },
          { label: 'Enabled',          value: list.filter((w: any) => w.is_active).length, color: '#22c55e' },
          { label: 'Total executions', value: list.reduce((acc: number, w: any) => acc + (w.run_count || 0), 0), color: '#fbbf24' },
        ].map(({ label, value, color }) => (
          <div key={label} className="metric-card">
            <p className="metric-label">{label}</p>
            <p className="metric-value" style={{ color }}>{value}</p>
          </div>
        ))}
      </div>

      {/* ── Workflow list ── */}
      {isLoading ? (
        <p style={{ fontSize: 12, color: 'var(--text-3)' }}>Loading workflows…</p>
      ) : list.length === 0 ? (
        <div className="card" style={{ padding: 24, textAlign: 'center' }}>
          <p style={{ fontSize: 13, color: 'var(--text-3)' }}>No workflows yet — create one to get started.</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {list.map((wf: any) => {
            const isExp = expanded === wf.id
            return (
              <div
                key={wf.id}
                className="card"
                style={{
                  padding: 0, overflow: 'hidden',
                  border: `1px solid ${wf.is_active ? 'rgba(37,99,235,0.2)' : 'var(--line)'}`,
                }}
              >
                {/* Header row */}
                <button
                  style={{
                    display: 'flex', alignItems: 'center', gap: 12, padding: '14px 16px',
                    width: '100%', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left',
                  }}
                  onClick={() => setExpanded(isExp ? null : wf.id)}
                >
                  <div
                    style={{
                      width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                      background: wf.is_active ? '#22c55e' : '#334155',
                      boxShadow: wf.is_active ? '0 0 6px rgba(34,197,94,0.5)' : 'none',
                    }}
                  />

                  <div
                    style={{
                      width: 34, height: 34, borderRadius: 7, flexShrink: 0,
                      background: wf.is_active ? 'rgba(37,99,235,0.12)' : 'rgba(96,130,182,0.08)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}
                  >
                    <Workflow size={16} color={wf.is_active ? '#60a5fa' : '#475569'} />
                  </div>

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', marginBottom: 2 }}>
                      {wf.name}
                    </p>
                    <p style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {wf.description || 'No description'}
                    </p>
                  </div>

                  <span style={{ fontSize: 11, color: 'var(--text-3)', fontVariantNumeric: 'tabular-nums', flexShrink: 0 }}>
                    {wf.run_count || 0} runs
                  </span>

                  <ChevronRight
                    size={14}
                    color="var(--text-3)"
                    style={{ transition: 'transform 0.15s', transform: isExp ? 'rotate(90deg)' : 'none', flexShrink: 0 }}
                  />
                </button>

                {/* Expanded detail */}
                {isExp && (
                  <div
                    style={{
                      borderTop: '1px solid var(--line)',
                      padding: '14px 16px',
                      background: 'rgba(11,16,26,0.5)',
                      display: 'grid', gridTemplateColumns: '1fr auto', gap: 16,
                    }}
                  >
                    <div>
                      <p style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-3)', marginBottom: 10 }}>
                        Nodes ({(wf.nodes || []).length})
                      </p>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                        {(wf.nodes || []).map((node: any, i: number) => (
                          <div key={node.id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span
                              style={{
                                width: 20, height: 20, borderRadius: '50%', flexShrink: 0,
                                background: 'rgba(37,99,235,0.15)', border: '1px solid rgba(37,99,235,0.25)',
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                fontSize: 9, fontWeight: 700, color: '#60a5fa', fontVariantNumeric: 'tabular-nums',
                              }}
                            >
                              {i + 1}
                            </span>
                            <span style={{ fontSize: 12, color: 'var(--text-2)' }}>
                              {node.data?.label || node.type}
                            </span>
                          </div>
                        ))}
                        {(wf.nodes || []).length === 0 && (
                          <span style={{ fontSize: 12, color: 'var(--text-3)' }}>Empty — open the builder to add nodes.</span>
                        )}
                      </div>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-end' }}>
                      <div style={{ fontSize: 10, color: 'var(--text-3)', textAlign: 'right', marginBottom: 4 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 3 }}>
                          <Clock size={10} />
                          {wf.last_run_at
                            ? `Last run ${formatDistanceToNow(new Date(wf.last_run_at), { addSuffix: true })}`
                            : 'Never run'}
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <Zap size={10} />
                          Trigger: {describeTrigger(wf)}
                        </div>
                      </div>

                      <button
                        className="btn-primary"
                        style={{ fontSize: 11, padding: '5px 12px' }}
                        disabled={runMutation.isPending}
                        onClick={() => runMutation.mutate(wf.id)}
                      >
                        <Play size={11} /> Run now
                      </button>
                      <button
                        className="btn-secondary"
                        style={{ fontSize: 11, padding: '5px 12px' }}
                        disabled={toggleMutation.isPending}
                        onClick={() => toggleMutation.mutate({ id: wf.id, is_active: !wf.is_active })}
                      >
                        {wf.is_active ? 'Disable' : 'Enable'}
                      </button>
                      <button
                        className="btn-secondary"
                        style={{ fontSize: 11, padding: '5px 12px' }}
                        onClick={() => navigate(`/soar/${wf.id}/edit`)}
                      >
                        <Pencil size={11} /> Edit
                      </button>
                      <button
                        className="btn-secondary"
                        style={{ fontSize: 11, padding: '5px 12px', color: '#f87171' }}
                        onClick={() => {
                          if (confirm(`Delete workflow "${wf.name}"?`)) deleteMutation.mutate(wf.id)
                        }}
                      >
                        <Trash2 size={11} /> Delete
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* ── Shuffle CTA ── */}
      <div
        className="card"
        style={{
          padding: 20,
          background: 'linear-gradient(135deg, rgba(37,99,235,0.07) 0%, rgba(96,130,182,0.03) 100%)',
          border: '1px solid rgba(37,99,235,0.15)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div
            style={{
              width: 42, height: 42, borderRadius: 10, flexShrink: 0,
              background: 'rgba(37,99,235,0.15)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}
          >
            <Workflow size={20} color="#60a5fa" />
          </div>
          <div style={{ flex: 1 }}>
            <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)', marginBottom: 3 }}>
              Need more integrations?
            </p>
            <p style={{ fontSize: 12, color: 'var(--text-3)', lineHeight: 1.5 }}>
              The built-in builder covers alerts, cases, Slack, email, HTTP, and Wazuh active response. For 800+ third-party integrations, pair it with Shuffle SOAR.
            </p>
          </div>
          <a
            href="http://localhost:3001"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary"
            style={{ flexShrink: 0 }}
          >
            Open Shuffle
          </a>
        </div>
      </div>
    </div>
  )
}
