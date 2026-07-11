import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  CheckCircle2, XCircle, RefreshCw, ExternalLink,
  Wifi, WifiOff, ChevronDown, ChevronUp, Settings2
} from 'lucide-react'
import toast from 'react-hot-toast'
import { formatDistanceToNow } from 'date-fns'
import { api } from '../stores/auth'
import { connectorMeta, CATEGORY_COLOR, CATEGORY_TEXT } from '../lib/connectors'

export default function Connectors() {
  const qc = useQueryClient()
  const [editing, setEditing]   = useState<string | null>(null)
  const [editForm, setEditForm] = useState<any>({})
  const [expanded, setExpanded] = useState<string | null>(null)

  const { data: connectors, isLoading } = useQuery({
    queryKey: ['connectors'],
    queryFn: () => api.listConnectors().then((r) => r.data),
  })

  const verifyMutation = useMutation({
    mutationFn: (id: string) => api.verifyConnector(id),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['connectors'] })
      if (data.data.connected) toast.success('Connection verified')
      else toast.error(`Failed: ${data.data.detail}`)
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: any) => api.updateConnector(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['connectors'] })
      setEditing(null)
      toast.success('Connector updated')
    },
  })

  const online = (connectors || []).filter((c: any) => c.verified).length
  const total  = connectors?.length ?? 0
  const pct    = total > 0 ? Math.round((online / total) * 100) : 0

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Connectors</h1>
          <p className="page-sub">Integrations and external platform health</p>
        </div>
        <button
          className="btn-secondary"
          onClick={() => (connectors || []).forEach((c: any) => verifyMutation.mutate(c.id))}
        >
          <RefreshCw size={13} />
          Verify all
        </button>
      </div>

      {/* ── System health summary ───────────────────────────────────── */}
      <div className="card" style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)' }}>
            Platform health
          </p>
          <span
            style={{
              fontSize: 18, fontWeight: 700,
              color: pct === 100 ? '#4ade80' : pct > 60 ? '#fbbf24' : '#f87171',
              fontVariantNumeric: 'tabular-nums',
              letterSpacing: '-0.02em',
            }}
          >
            {pct}%
          </span>
        </div>
        <div style={{ height: 4, background: 'rgba(96,130,182,0.12)', borderRadius: 99, overflow: 'hidden' }}>
          <div
            style={{
              height: '100%',
              width: `${pct}%`,
              background: pct === 100
                ? 'linear-gradient(90deg, #16a34a, #22c55e)'
                : pct > 60
                  ? 'linear-gradient(90deg, #d97706, #f59e0b)'
                  : 'linear-gradient(90deg, #dc2626, #f43f5e)',
              borderRadius: 99,
              transition: 'width 0.6s cubic-bezier(0.4,0,0.2,1)',
            }}
          />
        </div>
        <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 8 }}>
          {online} of {total} connectors online
          {online < total && ` · ${total - online} offline`}
        </p>
      </div>

      {/* ── Connector grid ───────────────────────────────────────────── */}
      {isLoading && (
        <div className="empty-state"><RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} /><span>Loading…</span></div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 12 }}>
        {(connectors || []).map((c: any) => {
          const meta = connectorMeta(c.connector_type)
          const isEdit = editing === c.id
          const isExp  = expanded === c.id

          return (
            <div
              key={c.id}
              className="connector-card"
              style={{
                borderColor: c.verified
                  ? 'rgba(34,197,94,0.2)'
                  : 'rgba(244,63,94,0.12)',
              }}
            >
              {/* Card header */}
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                {/* Status icon */}
                <div
                  style={{
                    width: 38, height: 38, borderRadius: 8, flexShrink: 0,
                    background: c.verified ? 'rgba(34,197,94,0.1)' : 'rgba(244,63,94,0.08)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}
                >
                  {c.verified
                    ? <Wifi size={17} color="#22c55e" />
                    : <WifiOff size={17} color="#f43f5e" />}
                </div>

                {/* Name / desc */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                    <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>{meta.label}</span>
                    <span
                      style={{
                        fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                        letterSpacing: '0.1em', padding: '1px 6px', borderRadius: 3,
                        background: CATEGORY_COLOR[meta.category] || 'rgba(96,130,182,0.1)',
                        color: CATEGORY_TEXT[meta.category] || 'var(--text-3)',
                      }}
                    >
                      {meta.category}
                    </span>
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--text-3)' }}>{meta.desc}</p>
                </div>

                {/* Online / offline pill */}
                <span className={c.verified ? 'pill-online status-pill' : 'pill-offline status-pill'}>
                  {c.verified ? <CheckCircle2 size={11} /> : <XCircle size={11} />}
                  {c.verified ? 'Online' : 'Offline'}
                </span>
              </div>

              {/* URL */}
              {c.url && (
                <div
                  style={{
                    marginTop: 10,
                    padding: '5px 10px',
                    background: 'var(--raise)',
                    borderRadius: 4,
                    border: '1px solid var(--line)',
                  }}
                >
                  <p style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {c.url}
                  </p>
                </div>
              )}

              {/* Edit form */}
              {isEdit && (
                <div
                  style={{
                    marginTop: 10, padding: '12px', background: 'var(--raise)',
                    borderRadius: 6, border: '1px solid var(--line)',
                    display: 'flex', flexDirection: 'column', gap: 8,
                  }}
                >
                  <input
                    className="input"
                    style={{ fontSize: 12 }}
                    placeholder="URL (https://…)"
                    value={editForm.url || ''}
                    onChange={(e) => setEditForm({ ...editForm, url: e.target.value })}
                  />
                  <input
                    className="input"
                    style={{ fontSize: 12 }}
                    placeholder="Username (if applicable)"
                    value={editForm.username || ''}
                    onChange={(e) => setEditForm({ ...editForm, username: e.target.value })}
                  />
                  <input
                    className="input"
                    style={{ fontSize: 12 }}
                    type="password"
                    placeholder="Password or API key"
                    value={editForm.password || ''}
                    onChange={(e) => setEditForm({ ...editForm, password: e.target.value })}
                  />
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button
                      className="btn-primary"
                      style={{ flex: 1, justifyContent: 'center', fontSize: 12, padding: '6px 12px' }}
                      onClick={() => updateMutation.mutate({ id: c.id, data: editForm })}
                    >
                      Save changes
                    </button>
                    <button
                      className="btn-secondary"
                      style={{ fontSize: 12, padding: '6px 12px' }}
                      onClick={() => setEditing(null)}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {/* Actions */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 10 }}>
                <button
                  className="btn-secondary"
                  style={{ fontSize: 11, padding: '4px 10px' }}
                  onClick={() => verifyMutation.mutate(c.id)}
                  disabled={verifyMutation.isPending}
                >
                  <RefreshCw size={12} /> Test
                </button>
                <button
                  className="btn-ghost"
                  style={{ fontSize: 11, padding: '4px 10px' }}
                  onClick={() => {
                    setEditing(isEdit ? null : c.id)
                    setEditForm({ url: c.url || '', username: c.username || '' })
                  }}
                >
                  <Settings2 size={12} />
                  {isEdit ? 'Cancel' : 'Configure'}
                </button>
                {meta.docs && meta.docs !== '#' && (
                  <a
                    href={meta.docs}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn-ghost"
                    style={{ fontSize: 11, padding: '4px 10px' }}
                  >
                    <ExternalLink size={11} /> Docs
                  </a>
                )}
                {c.last_verified && (
                  <span style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 'auto' }}>
                    Checked {formatDistanceToNow(new Date(c.last_verified), { addSuffix: true })}
                  </span>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
