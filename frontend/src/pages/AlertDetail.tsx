import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, RefreshCw, Shield, Clock, Server, Globe, Target,
  FolderOpen, Code2, AlertOctagon,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { format, formatDistanceToNow } from 'date-fns'
import { api } from '../stores/auth'

const SEV_LABEL: Record<string, string> = {
  critical: '#f43f5e', high: '#f97316', medium: '#f59e0b', low: '#67e8f9', info: '#64748b',
}
const STATUS_BADGE: Record<string, string> = {
  new:            'badge-critical',
  in_triage:      'badge-medium',
  escalated:      'badge-high',
  resolved:       'badge-success',
  false_positive: 'badge-muted',
}

function Section({ title, icon: Icon, children }: { title: string; icon?: any; children: React.ReactNode }) {
  return (
    <div className="card" style={{ padding: 16 }}>
      <p className="section-heading" style={{ margin: '0 0 12px', display: 'flex', alignItems: 'center', gap: 6 }}>
        {Icon && <Icon size={13} />} {title}
      </p>
      {children}
    </div>
  )
}

function Field({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <p style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 3 }}>{label}</p>
      <p style={{ fontSize: 12, color: 'var(--text-1)', fontFamily: mono ? 'JetBrains Mono,monospace' : undefined }}>
        {value ?? <span style={{ color: 'var(--text-3)' }}>—</span>}
      </p>
    </div>
  )
}

export default function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [linking, setLinking] = useState(false)

  const { data: a, isLoading } = useQuery({
    queryKey: ['alert', id],
    queryFn: () => api.getAlert(id!).then((r) => r.data),
    enabled: !!id,
  })

  const { data: cases } = useQuery({
    queryKey: ['cases', 'for-link'],
    queryFn: () => api.listCases({ limit: 200 }).then((r) => r.data),
    enabled: linking,
  })

  const updateMutation = useMutation({
    mutationFn: (data: any) => api.updateAlert(id!, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alert', id] })
      qc.invalidateQueries({ queryKey: ['alerts'] })
      toast.success('Alert updated')
      setLinking(false)
    },
  })

  if (isLoading) {
    return (
      <div className="empty-state">
        <RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} />
        <span>Loading alert…</span>
      </div>
    )
  }

  if (!a) {
    return (
      <div className="empty-state">
        <AlertOctagon size={18} color="#f43f5e" />
        <span>Alert not found</span>
      </div>
    )
  }

  const ips: string[] = a.iocs?.ips || []
  const ti = a.enrichment?.threat_intel

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button className="btn-ghost" style={{ padding: 6 }} onClick={() => navigate('/alerts')}>
            <ArrowLeft size={15} />
          </button>
          <div>
            <h1 className="page-title">{a.rule_name || '(no rule name)'}</h1>
            <p className="page-sub">
              {a.source} · {a.rule_id ? `rule ${a.rule_id}` : 'no rule id'}{a.level != null ? ` · level ${a.level}` : ''}
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className={`badge-${a.severity}`} style={{ textTransform: 'capitalize' }}>{a.severity}</span>
          <span className={STATUS_BADGE[a.status] || 'badge-muted'} style={{ textTransform: 'capitalize' }}>
            {a.status?.replace(/_/g, ' ')}
          </span>
          {a.status === 'new' && (
            <button className="btn-secondary" onClick={() => updateMutation.mutate({ status: 'in_triage' })}>
              Triage
            </button>
          )}
          {a.status !== 'resolved' && a.status !== 'false_positive' && (
            <button className="btn-ghost" onClick={() => updateMutation.mutate({ status: 'resolved' })}>
              Resolve
            </button>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, alignItems: 'start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* ── Overview ─────────────────────────────────────────────── */}
          <Section title="Overview" icon={Shield}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
              <Field label="Description" value={a.description} />
              <Field label="Alert time" value={format(new Date(a.alert_time), 'PPpp')} />
              <Field label="Ingested" value={formatDistanceToNow(new Date(a.created_at), { addSuffix: true })} />
            </div>
          </Section>

          {/* ── Agent / network ──────────────────────────────────────── */}
          <Section title="Agent & network" icon={Server}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
              <Field label="Agent" value={a.agent_name} />
              <Field label="Agent ID" value={a.agent_id} mono />
              <Field label="Agent IP" value={a.agent_ip} mono />
              <Field label="Source IP" value={a.src_ip} mono />
              <Field label="Destination IP" value={a.dst_ip} mono />
              <Field label="Username" value={a.username} />
            </div>
          </Section>

          {/* ── MITRE ────────────────────────────────────────────────── */}
          {(a.mitre_id || a.mitre_tactic) && (
            <Section title="MITRE ATT&CK" icon={Target}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                <Field label="Technique" value={a.mitre_id} mono />
                <Field label="Tactic" value={a.mitre_tactic} />
              </div>
            </Section>
          )}

          {/* ── Threat intel / IOCs ─────────────────────────────────── */}
          {(ips.length > 0 || ti) && (
            <Section title="Threat intelligence" icon={Globe}>
              {ips.length > 0 && (
                <div style={{ marginBottom: ti ? 12 : 0 }}>
                  <p style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                    Extracted IPs
                  </p>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {ips.map((ip) => (
                      <span key={ip} style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', padding: '2px 8px', borderRadius: 3, background: 'rgba(96,130,182,0.1)', color: '#67e8f9' }}>
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {ti && (
                <pre style={{
                  fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-2)',
                  background: 'var(--raise)', border: '1px solid var(--line)', borderRadius: 6,
                  padding: 10, overflow: 'auto', maxHeight: 240, margin: 0,
                }}>
                  {JSON.stringify(ti, null, 2)}
                </pre>
              )}
            </Section>
          )}

          {/* ── Raw alert ────────────────────────────────────────────── */}
          <Section title="Raw Wazuh alert" icon={Code2}>
            <pre style={{
              fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-2)',
              background: 'var(--raise)', border: '1px solid var(--line)', borderRadius: 6,
              padding: 10, overflow: 'auto', maxHeight: 400, margin: 0,
            }}>
              {a.raw_data ? JSON.stringify(a.raw_data, null, 2) : 'No raw data captured'}
            </pre>
          </Section>
        </div>

        {/* ── Sidebar ────────────────────────────────────────────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Section title="Case" icon={FolderOpen}>
            {a.case_id ? (
              <button className="btn-secondary" style={{ width: '100%', justifyContent: 'center' }} onClick={() => navigate(`/cases/${a.case_id}`)}>
                Open linked case
              </button>
            ) : linking ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <select
                  className="select"
                  style={{ width: '100%' }}
                  onChange={(e) => e.target.value && updateMutation.mutate({ case_id: e.target.value })}
                  defaultValue=""
                >
                  <option value="" disabled>Select a case…</option>
                  {(cases || []).map((c: any) => (
                    <option key={c.id} value={c.id}>#{c.case_number} — {c.title}</option>
                  ))}
                </select>
                <button className="btn-ghost" style={{ fontSize: 11 }} onClick={() => setLinking(false)}>Cancel</button>
              </div>
            ) : (
              <button className="btn-ghost" style={{ width: '100%', justifyContent: 'center', fontSize: 12 }} onClick={() => setLinking(true)}>
                Attach to a case
              </button>
            )}
          </Section>

          <Section title="Timing" icon={Clock}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <Field label="Alert time" value={formatDistanceToNow(new Date(a.alert_time), { addSuffix: true })} />
              <Field label="Ingested" value={format(new Date(a.created_at), 'PPpp')} />
              <Field label="Last updated" value={formatDistanceToNow(new Date(a.updated_at), { addSuffix: true })} />
              {a.triaged_at && <Field label="Triaged" value={format(new Date(a.triaged_at), 'PPpp')} />}
            </div>
          </Section>

          {a.tags && a.tags.length > 0 && (
            <Section title="Tags">
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {a.tags.map((t: string) => (
                  <span key={t} style={{ fontSize: 11, padding: '2px 8px', borderRadius: 3, background: 'rgba(96,130,182,0.1)', color: 'var(--text-2)' }}>
                    {t}
                  </span>
                ))}
              </div>
            </Section>
          )}
        </div>
      </div>
    </div>
  )
}
