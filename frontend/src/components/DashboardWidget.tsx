import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, AreaChart, Area,
} from 'recharts'
import { Fragment } from 'react'
import { X, CheckCircle } from 'lucide-react'

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: 'var(--raise)', border: '1px solid var(--line)', borderRadius: 6, padding: '8px 12px', fontSize: 12 }}>
      {label && <p style={{ color: 'var(--text-3)', marginBottom: 4 }}>{label}</p>}
      {payload.map((p: any) => (
        <p key={p.dataKey || p.name} style={{ color: p.payload?.color || p.color || 'var(--text-1)', fontWeight: 500 }}>
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  )
}

function EmptyWidget() {
  return (
    <div className="empty-state" style={{ padding: '24px 0' }}>
      <CheckCircle size={16} color="#22c55e" />
      <span>No data in this window</span>
    </div>
  )
}

function BarWidget({ widget }: { widget: any }) {
  const color = widget.config?.color || '#60a5fa'
  return (
    <ResponsiveContainer width="100%" height={Math.max(160, widget.data.length * 30)}>
      <BarChart data={widget.data} layout="vertical" margin={{ left: -4, right: 16, top: 4, bottom: 0 }}>
        <XAxis type="number" tick={{ fill: 'var(--text-3)', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <YAxis
          type="category" dataKey="name"
          tick={{ fill: 'var(--text-3)', fontSize: 11 }}
          axisLine={false} tickLine={false} width={170}
        />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(96,130,182,0.05)' }} />
        <Bar dataKey="value" radius={[0, 3, 3, 0]} barSize={14} fill={color} fillOpacity={0.85} />
      </BarChart>
    </ResponsiveContainer>
  )
}

function PieWidget({ widget }: { widget: any }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
      <ResponsiveContainer width={160} height={160}>
        <PieChart>
          <Pie
            data={widget.data} dataKey="value" nameKey="name"
            innerRadius={42} outerRadius={70} paddingAngle={2}
            strokeWidth={2} stroke="var(--base)"
          >
            {widget.data.map((d: any) => <Cell key={d.name} fill={d.color || '#60a5fa'} />)}
          </Pie>
          <Tooltip content={<ChartTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 7, flex: 1, minWidth: 0 }}>
        {widget.data.map((d: any) => (
          <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 12 }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: d.color || '#60a5fa', flexShrink: 0 }} />
            <span style={{ color: 'var(--text-2)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.name}</span>
            <span style={{ color: 'var(--text-3)', fontVariantNumeric: 'tabular-nums' }}>{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function LineWidget({ widget }: { widget: any }) {
  const color = widget.config?.color || '#60a5fa'
  return (
    <ResponsiveContainer width="100%" height={180}>
      <AreaChart data={widget.data} margin={{ left: -18, right: 8, top: 6, bottom: 0 }}>
        <defs>
          <linearGradient id={`grad-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.35} />
            <stop offset="100%" stopColor={color} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <XAxis dataKey="name" tick={{ fill: 'var(--text-3)', fontSize: 10 }} axisLine={false} tickLine={false} minTickGap={24} />
        <YAxis tick={{ fill: 'var(--text-3)', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip content={<ChartTooltip />} cursor={{ stroke: 'rgba(96,130,182,0.25)' }} />
        <Area
          type="monotone" dataKey="value" name={widget.config?.valueLabel || 'events'}
          stroke={color} strokeWidth={1.5} fill={`url(#grad-${color.replace('#', '')})`}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

function HistogramWidget({ widget }: { widget: any }) {
  const color = widget.config?.color || '#fbbf24'
  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={widget.data} margin={{ left: -18, right: 8, top: 6, bottom: 0 }}>
        <XAxis dataKey="name" tick={{ fill: 'var(--text-3)', fontSize: 10 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: 'var(--text-3)', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(96,130,182,0.05)' }} />
        <Bar dataKey="value" name={widget.config?.valueLabel || 'count'} radius={[3, 3, 0, 0]} fill={color} fillOpacity={0.85} />
      </BarChart>
    </ResponsiveContainer>
  )
}

function GaugeWidget({ widget }: { widget: any }) {
  const value = Number(widget.data) || 0
  const min = widget.config?.min ?? 0
  const max = widget.config?.max ?? 100
  const pct = Math.min(1, Math.max(0, (value - min) / (max - min)))
  const thresholds = widget.config?.thresholds || []
  const color = thresholds.find((t: any) => value <= t.upto)?.color || '#60a5fa'
  // Semicircle arc: radius 60, circumference of half-circle = PI * r
  const r = 60
  const half = Math.PI * r
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width={160} height={92} viewBox="0 0 160 92">
        <path d={`M 20 86 A ${r} ${r} 0 0 1 140 86`} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={12} strokeLinecap="round" />
        <path
          d={`M 20 86 A ${r} ${r} 0 0 1 140 86`}
          fill="none" stroke={color} strokeWidth={12} strokeLinecap="round"
          strokeDasharray={`${half * pct} ${half}`}
        />
        <text x={80} y={78} textAnchor="middle" fill="var(--text-1)" fontSize={26} fontWeight={700} style={{ fontVariantNumeric: 'tabular-nums' }}>
          {value}{widget.config?.unit || ''}
        </text>
      </svg>
      {widget.config?.detail && (
        <p style={{ fontSize: 11, color: 'var(--text-3)' }}>{widget.config.detail}</p>
      )}
    </div>
  )
}

function HeatmapWidget({ widget }: { widget: any }) {
  const xLabels: (string | number)[] = widget.config?.xLabels || []
  const yLabels: string[] = widget.config?.yLabels || []
  const color = widget.config?.color || '#60a5fa'
  const byCell: Record<string, number> = {}
  let maxVal = 0
  for (const d of widget.data) {
    byCell[`${d.y}|${d.x}`] = d.value
    if (d.value > maxVal) maxVal = d.value
  }
  return (
    <div style={{ overflowX: 'auto' }}>
      <div style={{ display: 'grid', gridTemplateColumns: `36px repeat(${xLabels.length}, 1fr)`, gap: 2, minWidth: 420 }}>
        <div />
        {xLabels.map((x) => (
          <div key={x} style={{ fontSize: 8, color: 'var(--text-3)', textAlign: 'center' }}>{x}</div>
        ))}
        {yLabels.map((y) => (
          <Fragment key={y}>
            <div style={{ fontSize: 10, color: 'var(--text-3)', display: 'flex', alignItems: 'center' }}>{y}</div>
            {xLabels.map((x) => {
              const v = byCell[`${y}|${x}`] || 0
              const intensity = maxVal ? v / maxVal : 0
              return (
                <div
                  key={`${y}-${x}`}
                  title={`${y} ${x}:00 — ${v} events`}
                  style={{
                    aspectRatio: '1.4', borderRadius: 2, minHeight: 14,
                    background: v ? color : 'rgba(255,255,255,0.03)',
                    opacity: v ? 0.15 + intensity * 0.85 : 1,
                  }}
                />
              )
            })}
          </Fragment>
        ))}
      </div>
    </div>
  )
}

function TableWidget({ widget }: { widget: any }) {
  const columns: string[] = widget.columns || Object.keys(widget.data[0] || {})
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead>
          <tr>{columns.map((c) => <th key={c}>{c}</th>)}</tr>
        </thead>
        <tbody>
          {widget.data.map((row: any, i: number) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c} style={{ fontSize: 12 }}>{row[c] === null || row[c] === undefined ? '—' : String(row[c])}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function WidgetBody({ widget }: { widget: any }) {
  if (widget.type === 'stat') {
    return <p style={{ fontSize: 32, fontWeight: 700, color: 'var(--text-1)', fontVariantNumeric: 'tabular-nums' }}>{widget.data ?? 0}</p>
  }
  if (widget.type === 'gauge') return <GaugeWidget widget={widget} />
  if (!widget.data || widget.data.length === 0) return <EmptyWidget />
  if (widget.type === 'bar') return <BarWidget widget={widget} />
  if (widget.type === 'pie') return <PieWidget widget={widget} />
  if (widget.type === 'line') return <LineWidget widget={widget} />
  if (widget.type === 'histogram') return <HistogramWidget widget={widget} />
  if (widget.type === 'heatmap') return <HeatmapWidget widget={widget} />
  if (widget.type === 'table') return <TableWidget widget={widget} />
  return null
}

export default function DashboardWidget({ widget, onRemove }: { widget: any; onRemove?: () => void }) {
  return (
    <div className="card" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
        <p className="section-heading" style={{ margin: 0 }}>{widget.title}</p>
        {onRemove && (
          <button className="btn-ghost" style={{ padding: 4 }} onClick={onRemove} title="Remove widget">
            <X size={13} />
          </button>
        )}
      </div>
      <WidgetBody widget={widget} />
    </div>
  )
}
