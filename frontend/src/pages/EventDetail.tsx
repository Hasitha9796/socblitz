import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, RefreshCw, Shield, Server, Target, Code2, ListChecks, AlertOctagon } from 'lucide-react'
import { format } from 'date-fns'
import { api } from '../stores/auth'

const LEVEL_BANDS = [
  { min: 12, color: '#f43f5e' },
  { min: 8,  color: '#f97316' },
  { min: 4,  color: '#f59e0b' },
  { min: 0,  color: '#67e8f9' },
]

function bandFor(level: number) {
  return LEVEL_BANDS.find((b) => level >= b.min) ?? LEVEL_BANDS[LEVEL_BANDS.length - 1]
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
      <p style={{ fontSize: 12, color: 'var(--text-1)', fontFamily: mono ? 'JetBrains Mono,monospace' : undefined, wordBreak: 'break-word' }}>
        {value ?? <span style={{ color: 'var(--text-3)' }}>—</span>}
      </p>
    </div>
  )
}

function TagList({ label, items }: { label: string; items?: string[] }) {
  if (!items || items.length === 0) return null
  return (
    <div>
      <p style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>{label}</p>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {items.map((t) => (
          <span key={t} style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', padding: '2px 8px', borderRadius: 3, background: 'rgba(96,130,182,0.1)', color: 'var(--text-2)' }}>
            {t}
          </span>
        ))}
      </div>
    </div>
  )
}

function flattenValue(v: any): string {
  if (v == null) return '—'
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

export default function EventDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()

  const { data: ev, isLoading } = useQuery({
    queryKey: ['event', id],
    queryFn: () => api.getEvent(id!).then((r) => r.data),
    enabled: !!id,
  })

  if (isLoading) {
    return (
      <div className="empty-state">
        <RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} />
        <span>Loading event…</span>
      </div>
    )
  }

  if (!ev) {
    return (
      <div className="empty-state">
        <AlertOctagon size={18} color="#f43f5e" />
        <span>Event not found</span>
      </div>
    )
  }

  const rule = ev.rule || {}
  const agent = ev.agent || {}
  const data = ev.data || {}
  const decoder = ev.decoder || {}
  const predecoder = ev.predecoder || {}
  const color = bandFor(rule.level ?? 0).color
  const timestamp = ev.timestamp || ev['@timestamp']
  const dataEntries = Object.entries(data)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="page-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button className="btn-ghost" style={{ padding: 6 }} onClick={() => navigate('/events')}>
            <ArrowLeft size={15} />
          </button>
          <div>
            <h1 className="page-title">{rule.description || '(no rule description)'}</h1>
            <p className="page-sub">
              {ev.manager?.name || 'wazuh'} · rule {rule.id ?? '—'} · timestamp {timestamp ? format(new Date(timestamp), 'PPpp') : '—'}
            </p>
          </div>
        </div>
        <span
          style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            fontSize: 12, fontWeight: 700, color,
            padding: '4px 12px', borderRadius: 4, background: color + '18',
          }}
        >
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: color }} />
          Level {rule.level ?? '—'}
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16, alignItems: 'start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* ── Overview ─────────────────────────────────────────────── */}
          <Section title="Overview" icon={Shield}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <Field label="Full log" value={ev.full_log} mono />
              <TagList label="Rule groups" items={rule.groups} />
            </div>
          </Section>

          {/* ── Extracted data (varies by event type) ───────────────── */}
          {dataEntries.length > 0 && (
            <Section title="Extracted data" icon={ListChecks}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {dataEntries.map(([k, v]) => (
                  <Field key={k} label={k} value={flattenValue(v)} mono />
                ))}
              </div>
            </Section>
          )}

          {/* ── Compliance mappings ──────────────────────────────────── */}
          {(rule.mitre || rule.pci_dss || rule.gdpr || rule.hipaa || rule.nist_800_53 || rule.tsc || rule.gpg13) && (
            <Section title="MITRE & compliance" icon={Target}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {rule.mitre?.id && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                    <Field label="MITRE technique" value={(rule.mitre.id || []).join(', ')} mono />
                    <Field label="MITRE tactic" value={(rule.mitre.tactic || []).join(', ')} />
                  </div>
                )}
                <TagList label="PCI DSS" items={rule.pci_dss} />
                <TagList label="GDPR" items={rule.gdpr} />
                <TagList label="HIPAA" items={rule.hipaa} />
                <TagList label="NIST 800-53" items={rule.nist_800_53} />
                <TagList label="TSC" items={rule.tsc} />
                <TagList label="GPG13" items={rule.gpg13} />
              </div>
            </Section>
          )}

          {/* ── Raw document ─────────────────────────────────────────── */}
          <Section title="Raw Wazuh document" icon={Code2}>
            <pre style={{
              fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-2)',
              background: 'var(--raise)', border: '1px solid var(--line)', borderRadius: 6,
              padding: 10, overflow: 'auto', maxHeight: 440, margin: 0,
            }}>
              {JSON.stringify(ev, null, 2)}
            </pre>
          </Section>
        </div>

        {/* ── Sidebar ────────────────────────────────────────────────── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <Section title="Agent" icon={Server}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <Field label="Name" value={agent.name} />
              <Field label="ID" value={agent.id} mono />
              <Field label="IP" value={agent.ip} mono />
            </div>
          </Section>

          {(decoder.name || predecoder.hostname) && (
            <Section title="Decoder">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <Field label="Decoder" value={decoder.name} mono />
                <Field label="Parent decoder" value={decoder.parent} mono />
                <Field label="Program" value={predecoder.program_name} mono />
                <Field label="Hostname" value={predecoder.hostname} mono />
              </div>
            </Section>
          )}
        </div>
      </div>
    </div>
  )
}
