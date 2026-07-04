import { useQuery } from '@tanstack/react-query'
import {
  Bell, FolderOpen, Monitor, Activity, Shield, AlertTriangle,
  CheckCircle, TrendingUp, TrendingDown, ArrowRight, Wifi, WifiOff
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, Cell
} from 'recharts'
import { api } from '../stores/auth'
import { formatDistanceToNow } from 'date-fns'
import { useNavigate } from 'react-router-dom'

/* ── Severity palette ─────────────────────────────────────────────────────── */
const SEV_COLOR: Record<string, string> = {
  critical: '#f43f5e',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#67e8f9',
  info:     '#64748b',
}
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

/* ── Mock 7-day trend (will be replaced when backend exposes it) ──────────── */
function makeTrend(peak: number) {
  return ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((day, i) => ({
    day,
    alerts: Math.max(0, Math.round(peak * (0.4 + Math.sin(i * 0.9) * 0.35 + Math.random() * 0.25))),
  }))
}

/* ── Threat level calculation ─────────────────────────────────────────────── */
function getThreatLevel(crit: number, high: number, total: number) {
  if (total === 0) return { label: 'Normal', color: '#22c55e', pct: 8 }
  const score = ((crit * 4 + high * 2) / (total * 4)) * 100
  if (score > 60) return { label: 'Critical', color: '#f43f5e', pct: Math.min(score, 95) }
  if (score > 30) return { label: 'Elevated', color: '#f97316', pct: score }
  if (score > 10) return { label: 'Guarded', color: '#f59e0b', pct: score }
  return { label: 'Normal', color: '#22c55e', pct: Math.max(score, 8) }
}

/* ── Custom tooltip ───────────────────────────────────────────────────────── */
function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null
  return (
    <div
      style={{
        background: 'var(--raise)', border: '1px solid var(--line)',
        borderRadius: 6, padding: '8px 12px', fontSize: 12,
      }}
    >
      <p style={{ color: 'var(--text-3)', marginBottom: 4 }}>{label}</p>
      {payload.map((p: any) => (
        <p key={p.dataKey} style={{ color: p.color || 'var(--text-1)', fontWeight: 500 }}>
          {p.value}
        </p>
      ))}
    </div>
  )
}

/* ── Metric card ──────────────────────────────────────────────────────────── */
function MetricCard({
  label, value, sub, icon: Icon, color, dimColor, trend, onClick
}: {
  label: string; value: string | number; sub?: string;
  icon: any; color: string; dimColor: string;
  trend?: 'up' | 'down' | null; onClick?: () => void
}) {
  return (
    <div className="metric-card" style={{ cursor: onClick ? 'pointer' : 'default' }} onClick={onClick}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
        <div
          style={{
            width: 34, height: 34, borderRadius: 6, flexShrink: 0,
            background: dimColor,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
        >
          <Icon size={16} color={color} />
        </div>
        {trend && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 11, color: trend === 'up' ? '#f43f5e' : '#22c55e' }}>
            {trend === 'up' ? <TrendingUp size={12} /> : <TrendingDown size={12} />}
          </div>
        )}
      </div>
      <div>
        <p className="metric-label">{label}</p>
        <p className="metric-value" style={{ color }}>{value}</p>
        {sub && <p className="metric-sub" style={{ marginTop: 2 }}>{sub}</p>}
      </div>
    </div>
  )
}

/* ── Connector pill ───────────────────────────────────────────────────────── */
function ConnectorPill({ c }: { c: any }) {
  const name = c.connector_type.replace(/_/g, ' ')
  return (
    <div
      style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '7px 10px',
        background: 'var(--raise)', borderRadius: 5,
        border: `1px solid ${c.verified ? 'rgba(34,197,94,0.2)' : 'rgba(244,63,94,0.15)'}`,
      }}
    >
      {c.verified
        ? <Wifi size={13} color="#22c55e" />
        : <WifiOff size={13} color="#f43f5e" />}
      <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-2)', textTransform: 'capitalize' }}>{name}</span>
    </div>
  )
}

/* ── Main dashboard ───────────────────────────────────────────────────────── */
export default function Dashboard() {
  const navigate = useNavigate()

  const { data: alertStats } = useQuery({
    queryKey: ['alert-stats'],
    queryFn: () => api.alertStats().then((r) => r.data),
    refetchInterval: 30_000,
  })
  const { data: alerts } = useQuery({
    queryKey: ['recent-alerts'],
    queryFn: () => api.listAlerts({ limit: 10 }).then((r) => r.data),
    refetchInterval: 30_000,
  })
  const { data: agents } = useQuery({
    queryKey: ['agents'],
    queryFn: () => api.listAgents().then((r) => r.data),
  })
  const { data: connectors } = useQuery({
    queryKey: ['connectors'],
    queryFn: () => api.listConnectors().then((r) => r.data),
  })

  const criticalCount = alertStats?.severity?.critical ?? 0
  const highCount     = alertStats?.severity?.high ?? 0
  const totalAlerts   = Object.values(alertStats?.severity ?? {}).reduce((a: number, b: any) => a + Number(b), 0)
  const newCount      = alertStats?.status?.new ?? 0
  const activeAgents  = (agents ?? []).filter((a: any) => a.status === 'active').length
  const totalAgents   = (agents ?? []).length
  const healthyConns  = (connectors ?? []).filter((c: any) => c.verified).length
  const totalConns    = (connectors ?? []).length
  const openCases     = 0  // shown as placeholder

  const threat = getThreatLevel(criticalCount, highCount, totalAlerts)
  const trend   = makeTrend(Math.max(totalAlerts, 20))

  const sevData = SEV_ORDER
    .map((s) => ({ name: s, count: Number(alertStats?.severity?.[s] ?? 0) }))
    .filter((d) => d.count > 0)

  const criticalAlerts = (alerts ?? [])
    .filter((a: any) => a.severity === 'critical' || a.severity === 'high')
    .slice(0, 8)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* ── Threat posture ─────────────────────────────────────────── */}
      <div
        className="card"
        style={{ padding: '16px 20px' }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
          <div>
            <p style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--text-3)' }}>
              Threat Posture
            </p>
            <p style={{ fontSize: 18, fontWeight: 700, color: threat.color, letterSpacing: '-0.01em', marginTop: 2 }}>
              {threat.label}
            </p>
          </div>
          <div style={{ textAlign: 'right' }}>
            <p style={{ fontSize: 11, color: 'var(--text-3)' }}>
              {criticalCount} critical · {highCount} high · {newCount} unacknowledged
            </p>
            <button
              onClick={() => navigate('/alerts')}
              style={{
                marginTop: 6, fontSize: 11, color: '#60a5fa',
                display: 'inline-flex', alignItems: 'center', gap: 3,
                background: 'none', border: 'none', cursor: 'pointer', padding: 0,
              }}
            >
              View all alerts <ArrowRight size={11} />
            </button>
          </div>
        </div>
        {/* Severity breakdown bar */}
        <div style={{ display: 'flex', height: 6, borderRadius: 99, overflow: 'hidden', gap: 2 }}>
          {SEV_ORDER.map((sev) => {
            const count = Number(alertStats?.severity?.[sev] ?? 0)
            const pct   = totalAlerts > 0 ? (count / totalAlerts) * 100 : 0
            if (pct < 0.5) return null
            return (
              <div
                key={sev}
                style={{
                  width: `${pct}%`, height: '100%',
                  background: SEV_COLOR[sev],
                  borderRadius: 99,
                  opacity: 0.85,
                }}
                title={`${sev}: ${count}`}
              />
            )
          })}
          {totalAlerts === 0 && (
            <div style={{ flex: 1, background: 'rgba(34,197,94,0.3)', borderRadius: 99 }} />
          )}
        </div>
      </div>

      {/* ── Key metrics ────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
        <MetricCard
          label="Total Alerts"
          value={totalAlerts}
          sub={`${newCount} new`}
          icon={Bell}
          color="#60a5fa"
          dimColor="rgba(37,99,235,0.12)"
          onClick={() => navigate('/alerts')}
        />
        <MetricCard
          label="Critical"
          value={criticalCount}
          sub={`${highCount} high severity`}
          icon={AlertTriangle}
          color={criticalCount > 0 ? '#f87171' : '#4ade80'}
          dimColor={criticalCount > 0 ? 'rgba(244,63,94,0.12)' : 'rgba(34,197,94,0.10)'}
          trend={criticalCount > 5 ? 'up' : null}
          onClick={() => navigate('/alerts')}
        />
        <MetricCard
          label="Active Agents"
          value={totalAgents > 0 ? `${activeAgents}/${totalAgents}` : '—'}
          sub={totalAgents > 0 ? `${Math.round((activeAgents / totalAgents) * 100)}% online` : 'No agents'}
          icon={Monitor}
          color="#4ade80"
          dimColor="rgba(34,197,94,0.10)"
          onClick={() => navigate('/agents')}
        />
        <MetricCard
          label="Connectors"
          value={`${healthyConns}/${totalConns}`}
          sub={healthyConns === totalConns ? 'All systems nominal' : `${totalConns - healthyConns} offline`}
          icon={Activity}
          color={healthyConns === totalConns ? '#67e8f9' : '#f59e0b'}
          dimColor={healthyConns === totalConns ? 'rgba(103,232,249,0.10)' : 'rgba(245,158,11,0.12)'}
          onClick={() => navigate('/connectors')}
        />
      </div>

      {/* ── Charts row ─────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 14 }}>
        {/* 7-day trend */}
        <div className="card">
          <p className="section-heading">Alert volume — 7 days</p>
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={trend} margin={{ left: -10, right: 4, top: 4, bottom: 0 }}>
              <defs>
                <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#2563eb" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#2563eb" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid vertical={false} stroke="rgba(96,130,182,0.08)" />
              <XAxis
                dataKey="day"
                tick={{ fill: 'var(--text-3)', fontSize: 11 }}
                axisLine={false} tickLine={false}
              />
              <YAxis
                tick={{ fill: 'var(--text-3)', fontSize: 11 }}
                axisLine={false} tickLine={false}
              />
              <Tooltip content={<ChartTooltip />} cursor={{ stroke: 'rgba(96,130,182,0.2)', strokeWidth: 1 }} />
              <Area
                type="monotone"
                dataKey="alerts"
                stroke="#2563eb"
                strokeWidth={2}
                fill="url(#alertGrad)"
                dot={false}
                activeDot={{ r: 4, fill: '#3b82f6', strokeWidth: 2, stroke: 'var(--lift)' }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity breakdown */}
        <div className="card">
          <p className="section-heading">By severity</p>
          {sevData.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={sevData} layout="vertical" margin={{ left: -4, right: 16, top: 4, bottom: 0 }}>
                <XAxis type="number" tick={{ fill: 'var(--text-3)', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis
                  type="category" dataKey="name"
                  tick={{ fill: 'var(--text-3)', fontSize: 11 }}
                  axisLine={false} tickLine={false} width={58}
                />
                <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(96,130,182,0.05)' }} />
                <Bar dataKey="count" radius={[0, 3, 3, 0]} barSize={16}>
                  {sevData.map((entry) => (
                    <Cell key={entry.name} fill={SEV_COLOR[entry.name] || '#64748b'} fillOpacity={0.85} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-state" style={{ padding: '24px 0' }}>
              <CheckCircle size={20} color="#22c55e" />
              <span>No alerts</span>
            </div>
          )}
        </div>
      </div>

      {/* ── Bottom row ──────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 14 }}>

        {/* Critical / high alerts table */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--line)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <p className="section-heading" style={{ marginBottom: 0 }}>Recent critical alerts</p>
            <button
              onClick={() => navigate('/alerts')}
              style={{
                fontSize: 11, color: '#60a5fa', background: 'none', border: 'none',
                cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 3,
              }}
            >
              View all <ArrowRight size={11} />
            </button>
          </div>
          <div className="tbl-wrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 8, padding: '10px 0 10px 14px' }}></th>
                  <th>Rule</th>
                  <th>Agent</th>
                  <th>MITRE</th>
                  <th>Status</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {criticalAlerts.map((a: any) => (
                  <tr key={a.id} className={`sev-${a.severity}`} style={{ cursor: 'pointer' }}
                      onClick={() => navigate('/alerts')}>
                    <td style={{ padding: '11px 0 11px 14px' }}>
                      <span className={`badge-${a.severity}`} style={{ gap: 0, padding: 0, background: 'none', boxShadow: 'none' }}>
                        <span />
                      </span>
                    </td>
                    <td style={{ maxWidth: 240 }}>
                      <p style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {a.rule_name || '(no rule name)'}
                      </p>
                      <p style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {a.description || ''}
                      </p>
                    </td>
                    <td>
                      <p style={{ fontSize: 12 }}>{a.agent_name || '—'}</p>
                      {a.agent_ip && <p style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-3)' }}>{a.agent_ip}</p>}
                    </td>
                    <td>
                      {a.mitre_id
                        ? <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: '#60a5fa' }}>{a.mitre_id}</span>
                        : <span style={{ color: 'var(--text-3)' }}>—</span>}
                    </td>
                    <td>
                      <span className={{
                        new:            'badge-critical',
                        in_triage:      'badge-medium',
                        escalated:      'badge-high',
                        resolved:       'badge-success',
                        false_positive: 'badge-muted',
                      }[a.status as string] || 'badge-muted'}>
                        {a.status?.replace('_', ' ')}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>
                      {formatDistanceToNow(new Date(a.alert_time), { addSuffix: true })}
                    </td>
                  </tr>
                ))}
                {criticalAlerts.length === 0 && (
                  <tr>
                    <td colSpan={6}>
                      <div className="empty-state">
                        <CheckCircle size={18} color="#22c55e" />
                        <span>No critical alerts</span>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Connector health */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <p className="section-heading" style={{ marginBottom: 0 }}>Connectors</p>
            <span style={{ fontSize: 11, color: healthyConns === totalConns ? '#4ade80' : '#f59e0b', fontWeight: 500 }}>
              {healthyConns}/{totalConns} online
            </span>
          </div>
          {/* Health bar */}
          <div style={{ height: 3, background: 'rgba(96,130,182,0.12)', borderRadius: 99, overflow: 'hidden' }}>
            <div
              style={{
                height: '100%',
                width: totalConns > 0 ? `${(healthyConns / totalConns) * 100}%` : '0',
                background: healthyConns === totalConns
                  ? 'linear-gradient(90deg, #22c55e, #4ade80)'
                  : 'linear-gradient(90deg, #2563eb, #60a5fa)',
                borderRadius: 99,
                transition: 'width 0.5s ease',
              }}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {(connectors ?? []).map((c: any) => (
              <ConnectorPill key={c.id} c={c} />
            ))}
            {(connectors ?? []).length === 0 && (
              <p style={{ fontSize: 12, color: 'var(--text-3)', textAlign: 'center', padding: '12px 0' }}>
                No connectors configured
              </p>
            )}
          </div>
          <button
            onClick={() => navigate('/connectors')}
            className="btn-ghost"
            style={{ width: '100%', justifyContent: 'center', marginTop: 4, fontSize: 12 }}
          >
            Manage connectors <ArrowRight size={12} />
          </button>
        </div>
      </div>
    </div>
  )
}
