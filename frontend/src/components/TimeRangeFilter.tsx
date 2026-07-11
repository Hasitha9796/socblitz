import { Clock } from 'lucide-react'

// A time-range selection shared by the Events and Alerts tabs. Relative presets
// stay "live": rangeToParams() resolves them against the current clock each time
// it's called (i.e. on every react-query refetch), so keep the TimeRange object
// — not its resolved ISO — in the query key.
export type TimeRange = { preset: string; start?: string; end?: string }

export const DEFAULT_RANGE: TimeRange = { preset: '24h' }

const PRESETS: { value: string; label: string; hours?: number }[] = [
  { value: '1h',     label: 'Last hour',     hours: 1   },
  { value: '6h',     label: 'Last 6 hours',  hours: 6   },
  { value: '24h',    label: 'Last 24 hours', hours: 24  },
  { value: '7d',     label: 'Last 7 days',   hours: 168 },
  { value: '30d',    label: 'Last 30 days',  hours: 720 },
  { value: 'custom', label: 'Custom range'              },
]

// Resolve a TimeRange into API query params (ISO-8601). Relative presets emit a
// `start` computed from now (end is left open so the backend uses "now").
export function rangeToParams(r: TimeRange): { start?: string; end?: string } {
  if (r.preset === 'custom') {
    const p: { start?: string; end?: string } = {}
    if (r.start) p.start = new Date(r.start).toISOString()
    if (r.end)   p.end   = new Date(r.end).toISOString()
    return p
  }
  const hours = PRESETS.find((x) => x.value === r.preset)?.hours ?? 24
  return { start: new Date(Date.now() - hours * 3600_000).toISOString() }
}

export function TimeRangeFilter({
  value,
  onChange,
}: {
  value: TimeRange
  onChange: (r: TimeRange) => void
}) {
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
      <Clock size={13} style={{ color: 'var(--text-3)' }} />
      <select
        className="select"
        style={{ width: 150, padding: '6px 28px 6px 10px' }}
        value={value.preset}
        onChange={(e) => onChange({ ...value, preset: e.target.value })}
      >
        {PRESETS.map((p) => (
          <option key={p.value} value={p.value}>{p.label}</option>
        ))}
      </select>

      {value.preset === 'custom' && (
        <>
          <input
            type="datetime-local"
            className="input"
            style={{ padding: '6px 10px', width: 195 }}
            value={value.start ?? ''}
            max={value.end || undefined}
            onChange={(e) => onChange({ ...value, start: e.target.value })}
          />
          <span style={{ fontSize: 11, color: 'var(--text-3)' }}>to</span>
          <input
            type="datetime-local"
            className="input"
            style={{ padding: '6px 10px', width: 195 }}
            value={value.end ?? ''}
            min={value.start || undefined}
            onChange={(e) => onChange({ ...value, end: e.target.value })}
          />
        </>
      )}
    </div>
  )
}
