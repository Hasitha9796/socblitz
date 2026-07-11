import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Shield, Search, RefreshCw, ExternalLink, AlertTriangle,
  CheckCircle, XCircle, Globe, Hash, Mail, Link2
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../stores/auth'

type IocType = 'ip' | 'domain' | 'hash' | 'url' | 'email'

const IOC_META: Record<IocType, { icon: any; label: string; placeholder: string }> = {
  ip:     { icon: Globe,         label: 'IP address', placeholder: '185.220.101.42'              },
  domain: { icon: Globe,         label: 'Domain',     placeholder: 'malicious-c2.example.com'    },
  hash:   { icon: Hash,          label: 'File hash',  placeholder: 'MD5 / SHA1 / SHA256'         },
  url:    { icon: Link2,         label: 'URL',        placeholder: 'https://evil.example/payload' },
  email:  { icon: Mail,          label: 'Email',      placeholder: 'phish@attacker.com'           },
}

const VERDICT_COLOR: Record<string, string> = {
  malicious:   '#f43f5e',
  suspicious:  '#f97316',
  clean:       '#22c55e',
  unknown:     '#94a3b8',
}

export default function ThreatIntel() {
  const [iocType, setIocType]  = useState<IocType>('ip')
  const [query,   setQuery]    = useState('')
  const [result,  setResult]   = useState<any>(null)
  const [loading, setLoading]  = useState(false)

  const { data: recentIOCs } = useQuery({
    queryKey: ['threat-intel-recent'],
    queryFn: () => api.mispEvents().then((r) => r.data),
  })

  async function handleLookup(e: React.FormEvent) {
    e.preventDefault()
    if (!query.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const { data } = await api.lookupIoc(query.trim(), iocType)
      setResult(data)
    } catch {
      toast.error('Lookup failed — check connector configuration')
    } finally {
      setLoading(false)
    }
  }

  const meta = IOC_META[iocType]
  const Icon = meta.icon

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Threat Intelligence</h1>
          <p className="page-sub">IOC lookup and intelligence enrichment</p>
        </div>
      </div>

      {/* ── Lookup panel ── */}
      <div className="card" style={{ padding: 20 }}>
        <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          IOC lookup
        </p>

        {/* Type selector */}
        <div style={{ display: 'flex', gap: 4, marginBottom: 12, flexWrap: 'wrap' }}>
          {(Object.entries(IOC_META) as [IocType, any][]).map(([type, m]) => {
            const TypeIcon = m.icon
            const active = iocType === type
            return (
              <button
                key={type}
                onClick={() => { setIocType(type); setResult(null) }}
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

        {/* Input + submit */}
        <form onSubmit={handleLookup} style={{ display: 'flex', gap: 8 }}>
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
              : <><Search size={13} /> Lookup</>}
          </button>
        </form>

        {/* Result */}
        {result && (() => {
          const verdictLabel = result.verdict?.status
            ?? (!result.sources
              ? 'unknown'
              : result.verdict?.malicious ? 'malicious' : 'clean')
          const confidence: number | null = result.verdict?.confidence ?? null
          const reasons: string[] = result.verdict?.reasons ?? []
          const sources: Record<string, any> = result.sources ?? {}
          const skipped: string[] = result.skipped ?? []

          return (
            <div
              style={{
                marginTop: 16,
                padding: 16,
                background: 'var(--raise)',
                border: `1px solid ${VERDICT_COLOR[verdictLabel] || 'var(--line)'}30`,
                borderRadius: 8,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                {verdictLabel === 'clean'
                  ? <CheckCircle size={18} color="#22c55e" />
                  : verdictLabel === 'malicious'
                    ? <XCircle size={18} color="#f43f5e" />
                    : <AlertTriangle size={18} color="#f97316" />}
                <span
                  style={{
                    fontSize: 16, fontWeight: 700, textTransform: 'capitalize',
                    color: VERDICT_COLOR[verdictLabel] || 'var(--text-1)',
                  }}
                >
                  {verdictLabel}
                </span>
                {confidence != null && (
                  <span
                    style={{
                      fontSize: 12, fontWeight: 600,
                      padding: '2px 8px', borderRadius: 3,
                      background: 'rgba(96,130,182,0.1)',
                      color: 'var(--text-2)',
                      fontVariantNumeric: 'tabular-nums',
                    }}
                  >
                    Confidence {confidence}/100
                  </span>
                )}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10 }}>
                <Field label="IOC value" value={result.value} mono />
                <Field label="Type" value={result.type} />
              </div>

              {result.note && (
                <p style={{ marginTop: 12, fontSize: 12, color: 'var(--text-3)' }}>{result.note}</p>
              )}

              {verdictLabel === 'unknown' && (
                <p style={{ marginTop: 12, fontSize: 12, color: '#f97316' }}>
                  No configured intel source had data on this IOC — this is not a clean verdict.
                </p>
              )}

              {skipped.length > 0 && (
                <p style={{ marginTop: 8, fontSize: 11, color: 'var(--text-3)' }}>
                  Not checked (no API key configured): {skipped.join(', ')}
                </p>
              )}

              {reasons.length > 0 && (
                <div style={{ marginTop: 12, display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                  {reasons.map((reason: string) => (
                    <span
                      key={reason}
                      style={{
                        fontSize: 11, padding: '2px 8px', borderRadius: 3,
                        background: 'rgba(244,63,94,0.1)',
                        border: '1px solid rgba(244,63,94,0.15)',
                        color: '#f87171',
                      }}
                    >
                      {reason}
                    </span>
                  ))}
                </div>
              )}

              {Object.keys(sources).length > 0 && (
                <div className="tbl-wrap" style={{ marginTop: 12 }}>
                  <table className="tbl">
                    <thead>
                      <tr>
                        <th style={{ width: 110 }}>Source</th>
                        <th style={{ width: 160 }}>Field</th>
                        <th>Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(sources).flatMap(([name, data]) => {
                        const rows: [string, any][] = data?.error
                          ? [['error', data.error]]
                          : Object.entries(data ?? {})
                        if (rows.length === 0) rows.push(['—', '—'])
                        return rows.map(([field, value], idx) => (
                          <tr key={`${name}-${field}`}>
                            {idx === 0 && (
                              <td
                                rowSpan={rows.length}
                                style={{
                                  fontSize: 12, fontWeight: 600, textTransform: 'capitalize',
                                  color: 'var(--text-2)', verticalAlign: 'top',
                                }}
                              >
                                {name}
                              </td>
                            )}
                            <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{field}</td>
                            <td
                              style={{
                                fontSize: 12, fontFamily: 'JetBrains Mono,monospace',
                                color: field === 'error' ? '#f87171' : 'var(--text-1)',
                                wordBreak: 'break-word',
                              }}
                            >
                              {formatValue(value)}
                            </td>
                          </tr>
                        ))
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )
        })()}
      </div>

      {/* ── Recent lookups ── */}
      {(recentIOCs || []).length > 0 && (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--line)' }}>
            <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Recent SocBlitz Threat Intel events
            </p>
          </div>
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Info</th>
                  <th>Org</th>
                  <th>Tags</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {(recentIOCs || []).map((raw: any, i: number) => {
                  const item = raw?.Event ?? raw ?? {}
                  const tags: string[] = (item.Tag ?? []).map((t: any) => t?.name).filter(Boolean)
                  return (
                    <tr key={item.id ?? i}>
                      <td style={{ fontSize: 12, fontFamily: 'JetBrains Mono,monospace', color: '#67e8f9' }}>
                        {item.id ?? '—'}
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-1)' }}>{item.info || '—'}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{item.Orgc?.name || '—'}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-3)' }}>
                        {tags.length > 0 ? tags.join(', ') : '—'}
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{item.date || '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

function formatValue(v: any): string {
  if (v === null || v === undefined || v === '') return '—'
  if (typeof v === 'boolean') return v ? 'yes' : 'no'
  if (Array.isArray(v)) {
    if (v.length === 0) return '—'
    return v.every((x) => typeof x !== 'object')
      ? v.join(', ')
      : `${v.length} item${v.length === 1 ? '' : 's'}`
  }
  if (typeof v === 'object') return JSON.stringify(v)
  return String(v)
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-3)', marginBottom: 3 }}>
        {label}
      </p>
      <p
        style={{
          fontSize: 12, color: 'var(--text-1)',
          fontFamily: mono ? 'JetBrains Mono,monospace' : undefined,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}
      >
        {value}
      </p>
    </div>
  )
}
