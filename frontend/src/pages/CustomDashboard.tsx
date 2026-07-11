import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Sparkles, RefreshCw, Save, Plus, Flame, Send, ChevronDown, Trash2, ShieldAlert } from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../stores/auth'
import DashboardWidget from '../components/DashboardWidget'

const HOURS_OPTIONS = [
  { label: '24h', value: 24 },
  { label: '7d', value: 168 },
]

const PROMPT_SUGGESTIONS = [
  'Show event volume over time',
  'Break down events by MITRE tactic',
  'Which agents are generating the most events?',
  'Show authentication failures as a line chart',
  'Top 5 source IPs as a pie chart',
  'What quiet but risky events might I be missing?',
]

const INSIGHTS_VIEW = '__insights__'
const VULNS_VIEW = '__vulns__'

function widgetKey(w: any) {
  return w.generator + JSON.stringify(w.params || {})
}

export default function CustomDashboard() {
  const qc = useQueryClient()
  const [hours, setHours] = useState(24)
  const [prompt, setPrompt] = useState('')
  const [view, setView] = useState<string>(INSIGHTS_VIEW)   // INSIGHTS_VIEW or a dashboard id
  const [menuOpen, setMenuOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState('')
  const [dashboardWidgets, setDashboardWidgets] = useState<any[]>([])
  const [dirty, setDirty] = useState(false)

  const isInsights = view === INSIGHTS_VIEW
  const isVulns = view === VULNS_VIEW
  const isBuiltin = isInsights || isVulns

  const { data: dashboards } = useQuery({
    queryKey: ['ai-dashboards'],
    queryFn: () => api.listDashboards().then((r) => r.data),
  })

  const { data: insights, isLoading: insightsLoading, refetch: refetchInsights } = useQuery({
    queryKey: ['ai-insights-flooding', hours],
    queryFn: () => api.floodingInsights(hours).then((r) => r.data),
    enabled: isInsights,
  })

  const { data: vulns, isLoading: vulnsLoading, refetch: refetchVulns } = useQuery({
    queryKey: ['ai-insights-vulns'],
    queryFn: () => api.vulnInsights(hours).then((r) => r.data),
    enabled: isVulns,
  })

  const { data: saved, isLoading: savedLoading } = useQuery({
    queryKey: ['ai-dashboard', view, hours],
    queryFn: () => api.getDashboard(view, hours).then((r) => r.data),
    enabled: !isInsights,
  })

  useEffect(() => {
    if (saved?.widgets && !dirty) setDashboardWidgets(saved.widgets)
  }, [saved, dirty])

  // Reset local edits when switching dashboards
  useEffect(() => {
    setDashboardWidgets([])
    setDirty(false)
  }, [view])

  const generateMutation = useMutation({
    mutationFn: (p: string) => api.generateDashboard(p, hours).then((r) => r.data),
    onError: () => toast.error('Could not reach the Wazuh indexer to build widgets'),
  })

  const createMutation = useMutation({
    mutationFn: (name: string) => api.createDashboard(name).then((r) => r.data),
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ['ai-dashboards'] })
      setView(d.id)
      setCreating(false)
      setNewName('')
      toast.success(`Dashboard "${d.name}" created`)
    },
    onError: () => toast.error('Failed to create dashboard'),
  })

  const saveMutation = useMutation({
    mutationFn: () => {
      const name = (dashboards || []).find((d: any) => d.id === view)?.name || 'My dashboard'
      return api.saveDashboard(view, name, dashboardWidgets).then((r) => r.data)
    },
    onSuccess: (data) => {
      qc.setQueryData(['ai-dashboard', view, hours], data)
      qc.invalidateQueries({ queryKey: ['ai-dashboards'] })
      setDirty(false)
      toast.success('Dashboard saved')
    },
    onError: () => toast.error('Failed to save dashboard'),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.deleteDashboard(view),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ai-dashboards'] })
      setView(INSIGHTS_VIEW)
      toast.success('Dashboard deleted')
    },
    onError: () => toast.error('Failed to delete dashboard'),
  })

  function addWidget(w: any) {
    if (isBuiltin) {
      toast('Select or create a dashboard first (dropdown at the top)', { icon: '👆' })
      return
    }
    setDashboardWidgets((prev) => {
      const key = widgetKey(w)
      const withoutDup = prev.filter((x) => widgetKey(x) !== key)
      return [...withoutDup, w]
    })
    setDirty(true)
    toast.success(`Added "${w.title}" to the dashboard`)
  }

  function removeWidget(idx: number) {
    setDashboardWidgets((prev) => prev.filter((_, i) => i !== idx))
    setDirty(true)
  }

  function handleGenerate() {
    if (!prompt.trim()) return
    generateMutation.mutate(prompt.trim())
  }

  const generated = generateMutation.data
  const currentName = isInsights
    ? 'Flooding & noise insights'
    : isVulns
    ? 'Vulnerability dashboard'
    : (dashboards || []).find((d: any) => d.id === view)?.name || 'Dashboard'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* ── Header ──────────────────────────────────────────────────── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-sub">AI agent view of your Wazuh events — pick a dashboard or build widgets by prompt</p>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {HOURS_OPTIONS.map((o) => (
            <button
              key={o.value}
              className={hours === o.value ? 'btn-secondary' : 'btn-ghost'}
              style={{ fontSize: 12, padding: '5px 12px' }}
              onClick={() => setHours(o.value)}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Dashboard selector ──────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, position: 'relative' }}>
        <button
          className="btn-secondary"
          style={{ fontSize: 13, padding: '7px 14px', display: 'flex', alignItems: 'center', gap: 8 }}
          onClick={() => setMenuOpen((o) => !o)}
        >
          {isInsights && <Flame size={13} color="#f97316" />}
          {isVulns && <ShieldAlert size={13} color="#f43f5e" />}
          {currentName}
          <ChevronDown size={13} style={{ transition: 'transform 0.15s', transform: menuOpen ? 'rotate(180deg)' : 'none' }} />
        </button>

        {!isBuiltin && (
          <>
            <button
              className="btn-primary"
              style={{ fontSize: 12, padding: '6px 12px' }}
              onClick={() => saveMutation.mutate()}
              disabled={!dirty || saveMutation.isPending}
            >
              <Save size={12} /> {saveMutation.isPending ? 'Saving…' : 'Save'}
            </button>
            <button
              className="btn-secondary"
              style={{ fontSize: 12, padding: '6px 12px', color: '#f87171' }}
              onClick={() => { if (confirm(`Delete dashboard "${currentName}"?`)) deleteMutation.mutate() }}
            >
              <Trash2 size={12} /> Delete
            </button>
          </>
        )}
        {isBuiltin && (
          <button
            className="btn-ghost"
            style={{ fontSize: 11, padding: '6px 12px' }}
            onClick={() => (isInsights ? refetchInsights() : refetchVulns())}
          >
            <RefreshCw size={12} className={(isInsights ? insightsLoading : vulnsLoading) ? 'animate-spin' : ''} /> Refresh
          </button>
        )}

        {menuOpen && (
          <div
            className="card"
            style={{
              position: 'absolute', top: '110%', left: 0, zIndex: 30, minWidth: 260,
              padding: 6, display: 'flex', flexDirection: 'column', gap: 2,
              boxShadow: '0 8px 24px rgba(0,0,0,0.45)',
            }}
          >
            <button
              className="btn-ghost"
              style={{ justifyContent: 'flex-start', fontSize: 12, padding: '8px 10px', display: 'flex', gap: 8, alignItems: 'center' }}
              onClick={() => { setView(INSIGHTS_VIEW); setMenuOpen(false) }}
            >
              <Flame size={12} color="#f97316" /> Flooding &amp; noise insights
            </button>
            <button
              className="btn-ghost"
              style={{ justifyContent: 'flex-start', fontSize: 12, padding: '8px 10px', display: 'flex', gap: 8, alignItems: 'center' }}
              onClick={() => { setView(VULNS_VIEW); setMenuOpen(false) }}
            >
              <ShieldAlert size={12} color="#f43f5e" /> Vulnerability dashboard
            </button>
            {(dashboards || []).map((d: any) => (
              <button
                key={d.id}
                className="btn-ghost"
                style={{ justifyContent: 'flex-start', fontSize: 12, padding: '8px 10px', display: 'flex', gap: 8, alignItems: 'center' }}
                onClick={() => { setView(d.id); setMenuOpen(false) }}
              >
                <Sparkles size={12} color="#60a5fa" /> {d.name}
                <span style={{ marginLeft: 'auto', color: 'var(--text-3)', fontSize: 10 }}>{d.widget_count} widgets</span>
              </button>
            ))}
            <div style={{ borderTop: '1px solid var(--line)', margin: '4px 0' }} />
            {creating ? (
              <div style={{ display: 'flex', gap: 6, padding: '4px 6px' }}>
                <input
                  className="input"
                  autoFocus
                  style={{ flex: 1, fontSize: 12 }}
                  placeholder="Dashboard name"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && newName.trim() && createMutation.mutate(newName.trim())}
                />
                <button
                  className="btn-primary"
                  style={{ fontSize: 11, padding: '4px 10px' }}
                  disabled={!newName.trim() || createMutation.isPending}
                  onClick={() => createMutation.mutate(newName.trim())}
                >
                  Create
                </button>
              </div>
            ) : (
              <button
                className="btn-ghost"
                style={{ justifyContent: 'flex-start', fontSize: 12, padding: '8px 10px', display: 'flex', gap: 8, alignItems: 'center', color: '#60a5fa' }}
                onClick={() => setCreating(true)}
              >
                <Plus size={12} /> New dashboard
              </button>
            )}
          </div>
        )}
      </div>

      {/* ── Selected view ───────────────────────────────────────────── */}
      {isInsights ? (
        insightsLoading ? (
          <div className="empty-state"><RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} /><span>Analyzing events…</span></div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
            {(insights?.widgets || []).map((w: any) => (
              <DashboardWidget key={w.title} widget={w} />
            ))}
          </div>
        )
      ) : isVulns ? (
        vulnsLoading ? (
          <div className="empty-state"><RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} /><span>Scanning vulnerability state…</span></div>
        ) : (vulns?.widgets || []).every((w: any) => !w.data || (Array.isArray(w.data) && w.data.length === 0)) ? (
          <div className="empty-state">
            <ShieldAlert size={16} color="#f43f5e" />
            <span>No vulnerability data yet — enroll Wazuh agents with vulnerability detection enabled and findings will appear here</span>
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
            {(vulns?.widgets || []).map((w: any) => (
              <DashboardWidget key={w.title} widget={w} />
            ))}
          </div>
        )
      ) : savedLoading ? (
        <div className="empty-state"><RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} /><span>Loading dashboard…</span></div>
      ) : dashboardWidgets.length === 0 ? (
        <div className="empty-state">
          <Sparkles size={16} color="#60a5fa" />
          <span>No widgets yet — ask the AI agent below to build some, then add them here</span>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
          {dashboardWidgets.map((w, i) => (
            <DashboardWidget key={widgetKey(w) + i} widget={w} onRemove={() => removeWidget(i)} />
          ))}
        </div>
      )}

      {/* ── AI prompt ───────────────────────────────────────────────── */}
      <div className="card" style={{ padding: 16 }}>
        <p className="section-heading" style={{ margin: '0 0 10px', display: 'flex', alignItems: 'center', gap: 6 }}>
          <Sparkles size={13} /> Ask the AI agent to build a widget
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            className="input"
            style={{ flex: 1 }}
            placeholder="e.g. top 5 source IPs as a pie chart · auth failures over time · events by category"
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleGenerate()}
          />
          <button className="btn-primary" onClick={handleGenerate} disabled={generateMutation.isPending || !prompt.trim()}>
            <Send size={13} /> Generate
          </button>
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 10 }}>
          {PROMPT_SUGGESTIONS.map((s) => (
            <button
              key={s}
              className="btn-ghost"
              style={{ fontSize: 11, padding: '4px 10px' }}
              onClick={() => { setPrompt(s); generateMutation.mutate(s) }}
            >
              {s}
            </button>
          ))}
        </div>

        {generateMutation.isPending && (
          <div className="empty-state" style={{ marginTop: 14 }}>
            <RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} />
            <span>Building widgets…</span>
          </div>
        )}

        {generated && !generateMutation.isPending && (
          <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <p style={{ fontSize: 12, color: 'var(--text-3)' }}>{generated.summary}</p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
              {generated.widgets.map((w: any) => (
                <div key={w.id} style={{ position: 'relative' }}>
                  <DashboardWidget widget={w} />
                  <button
                    className="btn-secondary"
                    style={{ position: 'absolute', top: 12, right: 40, fontSize: 11, padding: '3px 10px' }}
                    onClick={() => addWidget(w)}
                  >
                    <Plus size={12} /> Add to dashboard
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
