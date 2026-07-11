import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Fingerprint, RefreshCw, Monitor, Play, Circle, ExternalLink, Download, Copy,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../stores/auth'

const SUGGESTED_ARTIFACTS: Record<string, string[]> = {
  windows: [
    'Windows.System.Pstree',
    'Windows.Network.Netstat',
    'Windows.Sys.Users',
    'Windows.KapeFiles.Targets',
    'Windows.Forensics.Timeline',
  ],
  linux: [
    'Linux.Sys.Pslist',
    'Linux.Network.Netstat',
    'Linux.Sys.Users',
    'Linux.Sys.Crontab',
    'Linux.Search.FileFinder',
  ],
}

function lastSeen(usec?: number | string): { label: string; online: boolean } {
  const n = Number(usec)
  if (!n) return { label: 'never', online: false }
  const ms = n / 1000
  const ageMin = (Date.now() - ms) / 60000
  if (ageMin < 2)   return { label: 'online', online: true }
  if (ageMin < 60)  return { label: `${Math.round(ageMin)} min ago`, online: false }
  if (ageMin < 1440) return { label: `${Math.round(ageMin / 60)} h ago`, online: false }
  return { label: new Date(ms).toLocaleDateString(), online: false }
}

export default function Forensics() {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<any>(null)
  const [artifact, setArtifact] = useState('')
  const [collecting, setCollecting] = useState(false)
  const [showDeploy, setShowDeploy] = useState(false)

  const { data: deploy } = useQuery({
    queryKey: ['agent-deploy-command'],
    queryFn: () => api.agentDeployCommand().then((r) => r.data),
    enabled: showDeploy,
  })

  function copyCommand(cmd: string) {
    navigator.clipboard.writeText(cmd)
    toast.success('Command copied to clipboard')
  }

  const { data: clients, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['forensics-clients'],
    queryFn: () => api.forensicsClients().then((r) => r.data),
    refetchInterval: 60_000,
  })

  const { data: flows } = useQuery({
    queryKey: ['forensics-flows', selected?.client_id],
    queryFn: () => api.forensicsFlows(selected.client_id).then((r) => r.data),
    enabled: !!selected,
    refetchInterval: 15_000,
  })

  const [viewFlow, setViewFlow] = useState<{ flowId: string; artifact: string; artifacts: string[] } | null>(null)

  const { data: results, isLoading: resultsLoading } = useQuery({
    queryKey: ['forensics-results', selected?.client_id, viewFlow?.flowId, viewFlow?.artifact],
    queryFn: () => api.forensicsResults(selected.client_id, viewFlow!.flowId, viewFlow!.artifact).then((r) => r.data),
    enabled: !!selected && !!viewFlow,
  })

  function renderCell(v: any): string {
    if (v === null || v === undefined) return ''
    if (typeof v === 'object') return JSON.stringify(v)
    return String(v)
  }

  async function handleCollect(e: React.FormEvent) {
    e.preventDefault()
    if (!selected || !artifact.trim()) return
    setCollecting(true)
    try {
      await api.forensicsCollect(selected.client_id, artifact.trim())
      toast.success(`Collection started: ${artifact.trim()}`)
      setArtifact('')
      qc.invalidateQueries({ queryKey: ['forensics-flows', selected.client_id] })
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Collection failed')
    } finally {
      setCollecting(false)
    }
  }

  const os = (selected?.os_info?.system || '').toLowerCase().includes('win') ? 'windows' : 'linux'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Forensics</h1>
          <p className="page-sub">Velociraptor endpoint forensics — artifact collection and flow history</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            className={showDeploy ? 'btn-primary' : 'btn-secondary'}
            onClick={() => setShowDeploy((v) => !v)}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
          >
            <Download size={13} /> Deploy agent
          </button>
          <a
            href="https://localhost:8889"
            target="_blank"
            rel="noreferrer"
            className="btn-secondary"
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, textDecoration: 'none' }}
          >
            <ExternalLink size={13} /> Velociraptor GUI
          </a>
          <button className="btn-secondary" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* ── Deploy SocBlitz Agent ── */}
      {showDeploy && (
        <div className="card" style={{ padding: 20 }}>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Deploy SocBlitz Agent
          </p>
          <p style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 14 }}>
            One command installs and enrolls <strong>both</strong> endpoint components — the Wazuh agent
            (SIEM telemetry) and the Velociraptor client (forensics). Run it as root / Administrator on each endpoint.
          </p>

          {deploy && !deploy.configured ? (
            <p style={{ fontSize: 12, color: '#f97316' }}>{deploy.hint}</p>
          ) : (
            (['linux', 'windows'] as const).map((platform) => (
              <div key={platform} style={{ marginBottom: 10 }}>
                <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-2)', marginBottom: 4, textTransform: 'capitalize' }}>
                  {platform === 'windows' ? 'Windows (elevated PowerShell)' : 'Linux'}
                </p>
                <div style={{ display: 'flex', gap: 8, alignItems: 'stretch' }}>
                  <code style={{
                    flex: 1, padding: '8px 10px', borderRadius: 4, fontSize: 11,
                    fontFamily: 'JetBrains Mono,monospace', color: '#67e8f9',
                    background: 'rgba(96,130,182,0.08)', border: '1px solid var(--line)',
                    overflowX: 'auto', whiteSpace: 'nowrap',
                  }}>
                    {deploy?.[platform] || 'Loading…'}
                  </code>
                  <button
                    className="btn-secondary"
                    disabled={!deploy?.[platform]}
                    onClick={() => copyCommand(deploy[platform])}
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                  >
                    <Copy size={13} /> Copy
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* ── Enrolled endpoints ── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--line)' }}>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Enrolled endpoints {clients ? `(${clients.length})` : ''}
          </p>
        </div>

        {isLoading ? (
          <p style={{ padding: 16, fontSize: 12, color: 'var(--text-3)' }}>Loading…</p>
        ) : (clients || []).length === 0 ? (
          <div style={{ padding: 24, textAlign: 'center' }}>
            <Fingerprint size={28} style={{ color: 'var(--text-3)', marginBottom: 8 }} />
            <p style={{ fontSize: 13, color: 'var(--text-2)', marginBottom: 4 }}>No endpoints enrolled yet</p>
            <p style={{ fontSize: 12, color: 'var(--text-3)', maxWidth: 520, margin: '0 auto' }}>
              Click <strong>Deploy agent</strong> above to get a one-command installer that enrolls
              the unified SocBlitz Agent (Wazuh + Velociraptor) — enrolled hosts appear here within a minute.
            </p>
          </div>
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th></th>
                  <th>Hostname</th>
                  <th>Client ID</th>
                  <th>OS</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {(clients || []).map((c: any) => {
                  const seen = lastSeen(c.last_seen_at)
                  const active = selected?.client_id === c.client_id
                  return (
                    <tr
                      key={c.client_id}
                      onClick={() => { setSelected(c); setViewFlow(null) }}
                      style={{ cursor: 'pointer', background: active ? 'rgba(37,99,235,0.12)' : undefined }}
                    >
                      <td style={{ width: 24 }}>
                        <Circle size={9} fill={seen.online ? '#22c55e' : '#64748b'} color={seen.online ? '#22c55e' : '#64748b'} />
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-1)', display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Monitor size={12} style={{ color: 'var(--text-3)' }} />
                        {c.os_info?.hostname || c.os_info?.fqdn || '—'}
                      </td>
                      <td style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: '#67e8f9' }}>{c.client_id}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-3)' }}>
                        {c.os_info?.system || '—'} {c.os_info?.release || ''}
                      </td>
                      <td style={{ fontSize: 11, color: seen.online ? '#22c55e' : 'var(--text-3)' }}>{seen.label}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Selected endpoint: collect + flows ── */}
      {selected && (
        <div className="card" style={{ padding: 20 }}>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Collect artifact — {selected.os_info?.hostname || selected.client_id}
          </p>

          <form onSubmit={handleCollect} style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
            <input
              className="input"
              style={{ flex: 1 }}
              placeholder="Artifact name, e.g. Windows.System.Pstree"
              value={artifact}
              onChange={(e) => setArtifact(e.target.value)}
              required
            />
            <button type="submit" className="btn-primary" disabled={collecting}>
              {collecting
                ? <><RefreshCw size={13} className="animate-spin" /> Starting…</>
                : <><Play size={13} /> Collect</>}
            </button>
          </form>

          <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 16 }}>
            {SUGGESTED_ARTIFACTS[os].map((name) => (
              <button
                key={name}
                type="button"
                onClick={() => setArtifact(name)}
                style={{
                  fontSize: 11, padding: '3px 10px', borderRadius: 3, cursor: 'pointer',
                  background: 'rgba(96,130,182,0.08)', border: '1px solid var(--line)',
                  color: 'var(--text-3)', fontFamily: 'JetBrains Mono,monospace',
                }}
              >
                {name}
              </button>
            ))}
          </div>

          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Recent flows
          </p>
          {(flows || []).length === 0 ? (
            <p style={{ fontSize: 12, color: 'var(--text-3)' }}>No collections yet for this endpoint.</p>
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Flow ID</th>
                    <th>Artifacts</th>
                    <th>State</th>
                    <th>Started</th>
                  </tr>
                </thead>
                <tbody>
                  {(flows || []).map((f: any) => {
                    const ctx = f.context ?? f
                    const state = ctx.state || '—'
                    const resultArtifacts: string[] = ctx.artifacts_with_results?.length
                      ? ctx.artifacts_with_results
                      : ctx.request?.artifacts || []
                    const firstArtifact = resultArtifacts[0]
                    const active = viewFlow?.flowId === ctx.session_id
                    return (
                      <tr
                        key={ctx.session_id}
                        onClick={() => firstArtifact && setViewFlow({ flowId: ctx.session_id, artifact: firstArtifact, artifacts: resultArtifacts })}
                        title={state === 'FINISHED' ? 'Click to view collected data' : undefined}
                        style={{ cursor: firstArtifact ? 'pointer' : undefined, background: active ? 'rgba(37,99,235,0.12)' : undefined }}
                      >
                        <td style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: '#67e8f9' }}>{ctx.session_id}</td>
                        <td style={{ fontSize: 12, color: 'var(--text-1)' }}>
                          {(ctx.request?.artifacts || []).join(', ') || '—'}
                        </td>
                        <td style={{
                          fontSize: 11, fontWeight: 600,
                          color: state === 'FINISHED' ? '#22c55e' : state === 'ERROR' ? '#f43f5e' : '#f97316',
                        }}>
                          {state}
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-3)' }}>
                          {ctx.create_time ? new Date(Number(ctx.create_time) / 1000).toLocaleString() : '—'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* ── Collected data for the selected flow ── */}
          {viewFlow && (
            <div style={{ marginTop: 16 }}>
              <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Collected data — {viewFlow.artifact}
                {results ? ` (${results.rows.length} of ${results.total_rows} rows)` : ''}
              </p>
              {viewFlow.artifacts.length > 1 && (
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 10 }}>
                  {viewFlow.artifacts.map((name) => (
                    <button
                      key={name}
                      type="button"
                      onClick={() => setViewFlow({ ...viewFlow, artifact: name })}
                      style={{
                        fontSize: 11, padding: '3px 10px', borderRadius: 3, cursor: 'pointer',
                        background: viewFlow.artifact === name ? 'rgba(37,99,235,0.25)' : 'rgba(96,130,182,0.08)',
                        border: '1px solid var(--line)',
                        color: viewFlow.artifact === name ? 'var(--text-1)' : 'var(--text-3)',
                        fontFamily: 'JetBrains Mono,monospace',
                      }}
                    >
                      {name.includes('/') ? name.split('/').pop() : name}
                    </button>
                  ))}
                </div>
              )}
              {resultsLoading ? (
                <p style={{ fontSize: 12, color: 'var(--text-3)' }}>Loading results…</p>
              ) : !results || results.rows.length === 0 ? (
                <p style={{ fontSize: 12, color: 'var(--text-3)' }}>No result rows for this artifact.</p>
              ) : (
                <div className="tbl-wrap" style={{ maxHeight: 420, overflowY: 'auto' }}>
                  <table className="tbl">
                    <thead>
                      <tr>
                        {results.columns.map((col: string) => <th key={col}>{col}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {results.rows.map((row: any[], i: number) => (
                        <tr key={i}>
                          {row.map((cell, j) => (
                            <td
                              key={j}
                              title={renderCell(cell)}
                              style={{
                                fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-1)',
                                maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                              }}
                            >
                              {renderCell(cell)}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
