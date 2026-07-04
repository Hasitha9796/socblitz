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
        {result && (
          <div
            style={{
              marginTop: 16,
              padding: 16,
              background: 'var(--raise)',
              border: `1px solid ${VERDICT_COLOR[result.verdict?.toLowerCase()] || 'var(--line)'}30`,
              borderRadius: 8,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              {result.verdict?.toLowerCase() === 'clean'
                ? <CheckCircle size={18} color="#22c55e" />
                : result.verdict?.toLowerCase() === 'malicious'
                  ? <XCircle size={18} color="#f43f5e" />
                  : <AlertTriangle size={18} color="#f97316" />}
              <span
                style={{
                  fontSize: 16, fontWeight: 700, textTransform: 'capitalize',
                  color: VERDICT_COLOR[result.verdict?.toLowerCase()] || 'var(--text-1)',
                }}
              >
                {result.verdict || 'Unknown'}
              </span>
              {result.score != null && (
                <span
                  style={{
                    fontSize: 12, fontWeight: 600,
                    padding: '2px 8px', borderRadius: 3,
                    background: 'rgba(96,130,182,0.1)',
                    color: 'var(--text-2)',
                    fontVariantNumeric: 'tabular-nums',
                  }}
                >
                  Score {result.score}/100
                </span>
              )}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10 }}>
              {result.ioc_value && (
                <Field label="IOC value" value={result.ioc_value} mono />
              )}
              {result.ioc_type && (
                <Field label="Type" value={result.ioc_type} />
              )}
              {result.country && (
                <Field label="Country" value={result.country} />
              )}
              {result.asn && (
                <Field label="ASN" value={result.asn} mono />
              )}
              {result.last_seen && (
                <Field label="Last seen" value={new Date(result.last_seen).toLocaleDateString()} />
              )}
              {result.source && (
                <Field label="Source" value={result.source} />
              )}
            </div>

            {result.tags && result.tags.length > 0 && (
              <div style={{ marginTop: 12, display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                {result.tags.map((tag: string) => (
                  <span
                    key={tag}
                    style={{
                      fontSize: 11, padding: '2px 8px', borderRadius: 3,
                      background: 'rgba(244,63,94,0.1)',
                      border: '1px solid rgba(244,63,94,0.15)',
                      color: '#f87171',
                    }}
                  >
                    {tag}
                  </span>
                ))}
              </div>
            )}

            {result.raw && (
              <details style={{ marginTop: 12 }}>
                <summary style={{ fontSize: 11, color: 'var(--text-3)', cursor: 'pointer', marginBottom: 6 }}>
                  Raw response
                </summary>
                <pre
                  style={{
                    fontSize: 11, color: 'var(--text-3)',
                    background: 'var(--void)', padding: 10, borderRadius: 4,
                    overflow: 'auto', maxHeight: 200,
                    fontFamily: 'JetBrains Mono,monospace',
                  }}
                >
                  {JSON.stringify(result.raw, null, 2)}
                </pre>
              </details>
            )}
          </div>
        )}
      </div>

      {/* ── Recent lookups ── */}
      {(recentIOCs || []).length > 0 && (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--line)' }}>
            <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Recent intelligence
            </p>
          </div>
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Verdict</th>
                  <th>IOC</th>
                  <th>Type</th>
                  <th>Score</th>
                  <th>Source</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {(recentIOCs || []).map((item: any, i: number) => (
                  <tr key={item.id || i}>
                    <td>
                      <span
                        style={{
                          display: 'inline-flex', alignItems: 'center', gap: 4,
                          fontSize: 11, fontWeight: 500, textTransform: 'capitalize',
                          color: VERDICT_COLOR[item.verdict?.toLowerCase()] || 'var(--text-3)',
                        }}
                      >
                        <span
                          style={{
                            width: 5, height: 5, borderRadius: '50%',
                            background: VERDICT_COLOR[item.verdict?.toLowerCase()] || 'var(--text-3)',
                          }}
                        />
                        {item.verdict || 'unknown'}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 12, fontFamily: 'JetBrains Mono,monospace', color: '#67e8f9' }}>
                        {item.ioc_value}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'uppercase' }}>
                      {item.ioc_type}
                    </td>
                    <td style={{ fontSize: 12, fontVariantNumeric: 'tabular-nums' }}>
                      {item.score != null ? item.score : '—'}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{item.source || '—'}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)' }}>
                      {item.last_seen ? new Date(item.last_seen).toLocaleDateString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
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
