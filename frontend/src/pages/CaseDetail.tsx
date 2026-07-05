import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeft, Plus, RefreshCw, Trash2, Send, CheckCircle2, Circle,
  Clock, Shield, AlertCircle, MessageSquare, ListChecks,
  Activity, Bell, UserPlus, UserMinus, PenSquare, Tag as TagIcon,
  HardDrive, Paperclip, StickyNote, FileDown, Target, Pencil, X,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { formatDistanceToNow } from 'date-fns'
import { api, useAuthStore } from '../stores/auth'

const PRIORITY_COLOR: Record<string, string> = { critical: '#f43f5e', high: '#f97316', medium: '#f59e0b', low: '#67e8f9' }
const STATUS_OPTIONS = ['open', 'in_progress', 'pending', 'resolved', 'closed']
const STATUS_COLOR: Record<string, string> = { open: '#60a5fa', in_progress: '#fbbf24', pending: '#a78bfa', resolved: '#22c55e', closed: '#64748b' }
const TLP_COLOR: Record<string, string> = { RED: '#f43f5e', AMBER: '#f97316', GREEN: '#22c55e', WHITE: '#94a3b8' }
const OBS_TYPES = ['ip', 'domain', 'hash', 'url', 'email']
const TASK_STATUS_ORDER = ['to_do', 'in_progress', 'done']
const TASK_STATUS_LABEL: Record<string, string> = { to_do: 'To do', in_progress: 'In progress', done: 'Done' }
const VERDICT_COLOR: Record<string, string> = { malicious: '#f43f5e', clean: '#22c55e', unknown: '#94a3b8' }
const TIMELINE_COLOR: Record<string, string> = {
  created: '#60a5fa', update: '#fbbf24', comment: '#67e8f9', observable: '#f87171',
  task: '#c084fc', manual: '#94a3b8', asset: '#fb923c', evidence: '#38bdf8', note: '#a3e635',
}

const ASSET_TYPES = ['server', 'workstation', 'laptop', 'mobile', 'network', 'cloud', 'other']
const ASSET_TYPE_LABEL: Record<string, string> = {
  server: 'Server', workstation: 'Workstation', laptop: 'Laptop', mobile: 'Mobile', network: 'Network device', cloud: 'Cloud resource', other: 'Other',
}
const COMPROMISE_STATUSES = ['unknown', 'investigating', 'compromised', 'clean']
const COMPROMISE_LABEL: Record<string, string> = { unknown: 'Unknown', investigating: 'Investigating', compromised: 'Compromised', clean: 'Clean' }
const COMPROMISE_COLOR: Record<string, string> = { unknown: '#94a3b8', investigating: '#fbbf24', compromised: '#f43f5e', clean: '#22c55e' }

const TABS = [
  { key: 'overview', label: 'Overview', icon: Activity },
  { key: 'timeline',  label: 'Timeline', icon: Clock },
  { key: 'alerts',    label: 'Alerts', icon: Bell },
  { key: 'iocs',      label: 'IOCs', icon: Shield },
  { key: 'assets',    label: 'Assets', icon: HardDrive },
  { key: 'evidence',  label: 'Evidence', icon: Paperclip },
  { key: 'tasks',     label: 'Tasks', icon: ListChecks },
  { key: 'notes',     label: 'Notes', icon: StickyNote },
  { key: 'comments',  label: 'Comments', icon: MessageSquare },
]

function Section({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="card" style={{ padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <p className="section-heading" style={{ margin: 0 }}>{title}</p>
        {action}
      </div>
      {children}
    </div>
  )
}

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const userId = useAuthStore((s) => s.userId)
  const fullName = useAuthStore((s) => s.fullName)
  const [tab, setTab] = useState('overview')

  const [noteDraft, setNoteDraft] = useState('')
  const [timelineMitre, setTimelineMitre] = useState<string[]>([])
  const [commentDraft, setCommentDraft] = useState('')
  const [commentInternal, setCommentInternal] = useState(true)
  const [obsForm, setObsForm] = useState({ obs_type: 'ip', value: '', tlp: 'AMBER', asset_id: '' })
  const [taskForm, setTaskForm] = useState({ title: '', due_date: '' })
  const [assetForm, setAssetForm] = useState({ name: '', asset_type: 'workstation', ip_address: '', description: '', compromise_status: 'unknown' })
  const [evidenceForm, setEvidenceForm] = useState({ filename: '', hash_sha256: '', description: '', custody_notes: '' })
  const [noteForm, setNoteForm] = useState({ title: '', content: '' })
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null)
  const [editingNoteDraft, setEditingNoteDraft] = useState({ title: '', content: '' })
  const [downloading, setDownloading] = useState(false)

  const { data: c, isLoading } = useQuery({
    queryKey: ['case', id],
    queryFn: () => api.getCase(id!).then((r) => r.data),
    enabled: !!id,
  })
  const { data: timeline } = useQuery({
    queryKey: ['case-timeline', id],
    queryFn: () => api.getCaseTimeline(id!).then((r) => r.data),
    enabled: !!id,
  })
  const { data: alerts } = useQuery({
    queryKey: ['case-alerts', id],
    queryFn: () => api.listCaseAlerts(id!).then((r) => r.data),
    enabled: !!id,
  })
  const { data: observables } = useQuery({
    queryKey: ['case-observables', id],
    queryFn: () => api.getObservables(id!).then((r) => r.data),
    enabled: !!id,
  })
  const { data: tasks } = useQuery({
    queryKey: ['case-tasks', id],
    queryFn: () => api.listCaseTasks(id!).then((r) => r.data),
    enabled: !!id,
  })
  const { data: comments } = useQuery({
    queryKey: ['case-comments', id],
    queryFn: () => api.getComments(id!).then((r) => r.data),
    enabled: !!id,
  })
  const { data: assets } = useQuery({
    queryKey: ['case-assets', id],
    queryFn: () => api.listCaseAssets(id!).then((r) => r.data),
    enabled: !!id,
  })
  const { data: evidenceList } = useQuery({
    queryKey: ['case-evidence', id],
    queryFn: () => api.listCaseEvidence(id!).then((r) => r.data),
    enabled: !!id,
  })
  const { data: notes } = useQuery({
    queryKey: ['case-notes', id],
    queryFn: () => api.listCaseNotes(id!).then((r) => r.data),
    enabled: !!id,
  })
  const { data: mitreTechniques } = useQuery({
    queryKey: ['mitre-techniques'],
    queryFn: () => api.listMitreTechniques().then((r) => r.data),
    staleTime: Infinity,
  })

  function invalidateCase() {
    qc.invalidateQueries({ queryKey: ['case', id] })
    qc.invalidateQueries({ queryKey: ['case-timeline', id] })
    qc.invalidateQueries({ queryKey: ['cases'] })
  }

  const updateCase = useMutation({
    mutationFn: (data: any) => api.updateCase(id!, data),
    onSuccess: invalidateCase,
    onError: () => toast.error('Failed to update case'),
  })

  const addTimelineNote = useMutation({
    mutationFn: (description: string) => api.addTimelineEvent(id!, description, timelineMitre),
    onSuccess: () => { setNoteDraft(''); setTimelineMitre([]); invalidateCase() },
  })

  const addComment = useMutation({
    mutationFn: () => api.addComment(id!, commentDraft, commentInternal),
    onSuccess: () => {
      setCommentDraft('')
      qc.invalidateQueries({ queryKey: ['case-comments', id] })
      qc.invalidateQueries({ queryKey: ['case-timeline', id] })
    },
  })

  const addObservable = useMutation({
    mutationFn: () => api.addObservable(id!, { ...obsForm, asset_id: obsForm.asset_id || null }),
    onSuccess: () => {
      setObsForm({ obs_type: 'ip', value: '', tlp: 'AMBER', asset_id: '' })
      qc.invalidateQueries({ queryKey: ['case-observables', id] })
      qc.invalidateQueries({ queryKey: ['case-timeline', id] })
      toast.success('Observable added — enrichment queued')
    },
  })

  const deleteObservable = useMutation({
    mutationFn: (obsId: string) => api.deleteObservable(id!, obsId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['case-observables', id] }),
  })

  const createTask = useMutation({
    mutationFn: () => api.createCaseTask(id!, {
      title: taskForm.title,
      due_date: taskForm.due_date || null,
    }),
    onSuccess: () => {
      setTaskForm({ title: '', due_date: '' })
      qc.invalidateQueries({ queryKey: ['case-tasks', id] })
      qc.invalidateQueries({ queryKey: ['case-timeline', id] })
    },
  })

  const updateTask = useMutation({
    mutationFn: ({ taskId, data }: any) => api.updateCaseTask(id!, taskId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['case-tasks', id] })
      qc.invalidateQueries({ queryKey: ['case-timeline', id] })
    },
  })

  const deleteTask = useMutation({
    mutationFn: (taskId: string) => api.deleteCaseTask(id!, taskId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['case-tasks', id] }),
  })

  const createAsset = useMutation({
    mutationFn: () => api.createCaseAsset(id!, { ...assetForm, ip_address: assetForm.ip_address || null }),
    onSuccess: () => {
      setAssetForm({ name: '', asset_type: 'workstation', ip_address: '', description: '', compromise_status: 'unknown' })
      qc.invalidateQueries({ queryKey: ['case-assets', id] })
      qc.invalidateQueries({ queryKey: ['case-timeline', id] })
    },
  })

  const updateAsset = useMutation({
    mutationFn: ({ assetId, data }: any) => api.updateCaseAsset(id!, assetId, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['case-assets', id] })
      qc.invalidateQueries({ queryKey: ['case-timeline', id] })
    },
  })

  const deleteAsset = useMutation({
    mutationFn: (assetId: string) => api.deleteCaseAsset(id!, assetId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['case-assets', id] }),
  })

  const createEvidence = useMutation({
    mutationFn: () => api.createCaseEvidence(id!, {
      ...evidenceForm,
      hash_sha256: evidenceForm.hash_sha256 || null,
    }),
    onSuccess: () => {
      setEvidenceForm({ filename: '', hash_sha256: '', description: '', custody_notes: '' })
      qc.invalidateQueries({ queryKey: ['case-evidence', id] })
      qc.invalidateQueries({ queryKey: ['case-timeline', id] })
    },
  })

  const deleteEvidence = useMutation({
    mutationFn: (evidenceId: string) => api.deleteCaseEvidence(id!, evidenceId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['case-evidence', id] }),
  })

  const createNote = useMutation({
    mutationFn: () => api.createCaseNote(id!, noteForm),
    onSuccess: () => {
      setNoteForm({ title: '', content: '' })
      qc.invalidateQueries({ queryKey: ['case-notes', id] })
      qc.invalidateQueries({ queryKey: ['case-timeline', id] })
    },
  })

  const updateNote = useMutation({
    mutationFn: ({ noteId, data }: any) => api.updateCaseNote(id!, noteId, data),
    onSuccess: () => {
      setEditingNoteId(null)
      qc.invalidateQueries({ queryKey: ['case-notes', id] })
    },
  })

  const deleteNote = useMutation({
    mutationFn: (noteId: string) => api.deleteCaseNote(id!, noteId),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['case-notes', id] }),
  })

  async function handleDownloadReport() {
    setDownloading(true)
    try {
      await api.downloadCaseReport(id!, c.case_number)
    } catch {
      toast.error('Failed to generate report')
    } finally {
      setDownloading(false)
    }
  }

  if (isLoading || !c) {
    return (
      <div className="empty-state">
        <RefreshCw size={16} className="animate-spin" style={{ color: 'var(--text-3)' }} />
        <span>Loading case…</span>
      </div>
    )
  }

  const isMine = c.assigned_to === userId

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Back ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <button
          className="btn-ghost"
          style={{ fontSize: 12, padding: '4px 8px' }}
          onClick={() => navigate('/cases')}
        >
          <ArrowLeft size={13} /> Back to cases
        </button>
        <button
          className="btn-secondary"
          style={{ fontSize: 12 }}
          disabled={downloading}
          onClick={handleDownloadReport}
        >
          <FileDown size={13} /> {downloading ? 'Generating…' : 'Generate report'}
        </button>
      </div>

      {/* ── Header ── */}
      <div className="card" style={{ padding: 20 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-3)', fontFamily: 'JetBrains Mono,monospace' }}>
                #{c.case_number}
              </span>
              <span
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                  fontSize: 11, fontWeight: 600, textTransform: 'capitalize',
                  color: PRIORITY_COLOR[c.priority] || 'var(--text-3)',
                }}
              >
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: PRIORITY_COLOR[c.priority] || 'var(--text-3)' }} />
                {c.priority}
              </span>
            </div>
            <h1 className="page-title" style={{ marginBottom: 4 }}>{c.title}</h1>
            {c.description && <p className="page-sub">{c.description}</p>}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <select
              className="select"
              style={{ fontSize: 12, color: STATUS_COLOR[c.status] }}
              value={c.status}
              onChange={(e) => updateCase.mutate({ status: e.target.value })}
            >
              {STATUS_OPTIONS.map((s) => (
                <option key={s} value={s}>{s.replace('_', ' ')}</option>
              ))}
            </select>
            <select
              className="select"
              style={{ fontSize: 12 }}
              value={c.priority}
              onChange={(e) => updateCase.mutate({ priority: e.target.value })}
            >
              {Object.keys(PRIORITY_COLOR).map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 20, marginTop: 16, paddingTop: 14, borderTop: '1px solid var(--line)', flexWrap: 'wrap' }}>
          <Meta label="Assignee">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 12, color: 'var(--text-1)' }}>
                {c.assignee_name || <span style={{ color: 'var(--text-3)' }}>Unassigned</span>}
              </span>
              {isMine ? (
                <button className="btn-ghost" style={{ fontSize: 10, padding: '2px 6px' }} onClick={() => updateCase.mutate({ assigned_to: null })}>
                  <UserMinus size={10} /> Unassign
                </button>
              ) : (
                <button className="btn-ghost" style={{ fontSize: 10, padding: '2px 6px' }} onClick={() => updateCase.mutate({ assigned_to: userId })}>
                  <UserPlus size={10} /> {c.assigned_to ? 'Take over' : 'Assign to me'}
                </button>
              )}
            </div>
          </Meta>

          <Meta label="TLP">
            <select
              className="select"
              style={{ fontSize: 11, padding: '3px 8px', color: TLP_COLOR[c.tlp] || 'var(--text-2)' }}
              value={c.tlp}
              onChange={(e) => updateCase.mutate({ tlp: e.target.value })}
            >
              {Object.keys(TLP_COLOR).map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </Meta>

          <Meta label="PAP">
            <select
              className="select"
              style={{ fontSize: 11, padding: '3px 8px', color: TLP_COLOR[c.pap] || 'var(--text-2)' }}
              value={c.pap}
              onChange={(e) => updateCase.mutate({ pap: e.target.value })}
            >
              {Object.keys(TLP_COLOR).map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </Meta>

          <Meta label="Opened">
            <span style={{ fontSize: 12, color: 'var(--text-2)' }}>
              {formatDistanceToNow(new Date(c.created_at), { addSuffix: true })}
            </span>
          </Meta>

          {c.closed_at && (
            <Meta label="Closed">
              <span style={{ fontSize: 12, color: 'var(--text-2)' }}>
                {formatDistanceToNow(new Date(c.closed_at), { addSuffix: true })}
              </span>
            </Meta>
          )}

          {c.tags && c.tags.length > 0 && (
            <Meta label="Tags">
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {c.tags.map((t: string) => (
                  <span key={t} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 10, padding: '2px 7px', borderRadius: 3, background: 'rgba(96,130,182,0.1)', color: 'var(--text-2)' }}>
                    <TagIcon size={9} /> {t}
                  </span>
                ))}
              </div>
            </Meta>
          )}
        </div>
      </div>

      {/* ── Tabs ── */}
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        {TABS.map((t) => {
          const Icon = t.icon
          const active = tab === t.key
          const count = t.key === 'alerts' ? (alerts?.length ?? 0)
            : t.key === 'iocs' ? (observables?.length ?? 0)
            : t.key === 'assets' ? (assets?.length ?? 0)
            : t.key === 'evidence' ? (evidenceList?.length ?? 0)
            : t.key === 'tasks' ? (tasks?.length ?? 0)
            : t.key === 'notes' ? (notes?.length ?? 0)
            : t.key === 'comments' ? (comments?.length ?? 0)
            : null
          return (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 6,
                padding: '6px 14px', borderRadius: 6, cursor: 'pointer',
                border: 'none', fontSize: 12, fontWeight: active ? 600 : 400,
                background: active ? 'rgba(37,99,235,0.15)' : 'transparent',
                color: active ? '#60a5fa' : 'var(--text-3)',
              }}
            >
              <Icon size={13} /> {t.label}
              {count != null && count > 0 && (
                <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 8, background: 'rgba(96,130,182,0.15)' }}>{count}</span>
              )}
            </button>
          )
        })}
      </div>

      {/* ── Overview ── */}
      {tab === 'overview' && (
        <Section title="Case summary">
          {c.summary ? (
            <p style={{ fontSize: 13, color: 'var(--text-1)', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{c.summary}</p>
          ) : (
            <p style={{ fontSize: 12, color: 'var(--text-3)' }}>{c.description || 'No summary yet.'}</p>
          )}
        </Section>
      )}

      {/* ── Timeline ── */}
      {tab === 'timeline' && (
        <Section title="Investigation timeline">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16 }}>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                className="input"
                style={{ flex: 1 }}
                placeholder="Log an investigation step…"
                value={noteDraft}
                onChange={(e) => setNoteDraft(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && noteDraft.trim() && addTimelineNote.mutate(noteDraft.trim())}
              />
              <button
                className="btn-primary"
                disabled={!noteDraft.trim() || addTimelineNote.isPending}
                onClick={() => addTimelineNote.mutate(noteDraft.trim())}
              >
                <PenSquare size={13} /> Log
              </button>
            </div>
            <MitreTagPicker options={mitreTechniques} selected={timelineMitre} onChange={setTimelineMitre} />
          </div>

          {(!timeline || timeline.length === 0) && (
            <div className="empty-state"><Clock size={16} /><span>No events logged yet</span></div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {(timeline || []).slice().reverse().map((e: any, i: number) => (
              <div key={e.id || i} style={{ display: 'flex', gap: 10, paddingBottom: 14, position: 'relative' }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flexShrink: 0 }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: TIMELINE_COLOR[e.type] || '#94a3b8', marginTop: 3 }} />
                  {i < timeline.length - 1 && <span style={{ width: 1, flex: 1, background: 'var(--line)', marginTop: 4 }} />}
                </div>
                <div style={{ paddingBottom: 4 }}>
                  <p style={{ fontSize: 12, color: 'var(--text-1)' }}>{e.description}</p>
                  <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>
                    {e.actor} · {e.timestamp ? formatDistanceToNow(new Date(e.timestamp), { addSuffix: true }) : ''}
                  </p>
                  {e.mitre_techniques && e.mitre_techniques.length > 0 && (
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 5 }}>
                      {e.mitre_techniques.map((tid: string) => (
                        <span key={tid} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'rgba(196,132,252,0.12)', color: '#c084fc' }}>
                          <Target size={9} /> {tid}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* ── Alerts ── */}
      {tab === 'alerts' && (
        <Section title="Linked alerts">
          {(!alerts || alerts.length === 0) ? (
            <div className="empty-state"><Bell size={16} /><span>No alerts linked to this case</span></div>
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr><th>Severity</th><th>Rule</th><th>Status</th><th>Agent</th><th>Time</th></tr>
                </thead>
                <tbody>
                  {alerts.map((a: any) => (
                    <tr key={a.id}>
                      <td style={{ fontSize: 11, textTransform: 'capitalize', color: 'var(--text-2)' }}>{a.severity}</td>
                      <td style={{ fontSize: 12, color: 'var(--text-1)' }}>{a.rule_name || a.description || '—'}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-3)', textTransform: 'capitalize' }}>{a.status?.replace('_', ' ')}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{a.agent_name || '—'}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{formatDistanceToNow(new Date(a.alert_time), { addSuffix: true })}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      )}

      {/* ── IOCs ── */}
      {tab === 'iocs' && (
        <Section title="Observables / IOCs">
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
            <select className="select" style={{ fontSize: 12 }} value={obsForm.obs_type} onChange={(e) => setObsForm({ ...obsForm, obs_type: e.target.value })}>
              {OBS_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <input
              className="input"
              style={{ flex: 1, minWidth: 180 }}
              placeholder="Value (e.g. 185.220.101.42)"
              value={obsForm.value}
              onChange={(e) => setObsForm({ ...obsForm, value: e.target.value })}
            />
            <select className="select" style={{ fontSize: 12 }} value={obsForm.tlp} onChange={(e) => setObsForm({ ...obsForm, tlp: e.target.value })}>
              {Object.keys(TLP_COLOR).map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <select className="select" style={{ fontSize: 12 }} value={obsForm.asset_id} onChange={(e) => setObsForm({ ...obsForm, asset_id: e.target.value })}>
              <option value="">No linked asset</option>
              {(assets || []).map((a: any) => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
            <button
              className="btn-primary"
              disabled={!obsForm.value.trim() || addObservable.isPending}
              onClick={() => addObservable.mutate()}
            >
              <Plus size={13} /> Add
            </button>
          </div>

          {(!observables || observables.length === 0) ? (
            <div className="empty-state"><Shield size={16} /><span>No observables yet</span></div>
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr><th>Type</th><th>Value</th><th>TLP</th><th>Asset</th><th>Verdict</th><th></th></tr>
                </thead>
                <tbody>
                  {observables.map((o: any) => {
                    const verdict = o.enrichment?.verdict?.malicious ? 'malicious' : o.enrichment ? 'clean' : 'unknown'
                    return (
                      <tr key={o.id}>
                        <td style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--text-3)' }}>{o.obs_type}</td>
                        <td style={{ fontSize: 12, fontFamily: 'JetBrains Mono,monospace', color: '#67e8f9' }}>{o.value}</td>
                        <td>
                          <span style={{ fontSize: 10, fontWeight: 600, color: TLP_COLOR[o.tlp] || 'var(--text-3)' }}>{o.tlp}</span>
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-2)' }}>{o.asset_name || <span style={{ color: 'var(--text-3)' }}>—</span>}</td>
                        <td>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, textTransform: 'capitalize', color: VERDICT_COLOR[verdict] }}>
                            <span style={{ width: 5, height: 5, borderRadius: '50%', background: VERDICT_COLOR[verdict] }} />
                            {verdict}
                          </span>
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button className="btn-ghost" style={{ fontSize: 11, padding: '3px 6px' }} onClick={() => deleteObservable.mutate(o.id)}>
                            <Trash2 size={12} />
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      )}

      {/* ── Assets ── */}
      {tab === 'assets' && (
        <Section title="Assets">
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
            <input
              className="input"
              style={{ flex: 1, minWidth: 160 }}
              placeholder="Hostname / asset name"
              value={assetForm.name}
              onChange={(e) => setAssetForm({ ...assetForm, name: e.target.value })}
            />
            <select className="select" style={{ fontSize: 12 }} value={assetForm.asset_type} onChange={(e) => setAssetForm({ ...assetForm, asset_type: e.target.value })}>
              {ASSET_TYPES.map((t) => <option key={t} value={t}>{ASSET_TYPE_LABEL[t]}</option>)}
            </select>
            <input
              className="input"
              style={{ width: 140 }}
              placeholder="IP address"
              value={assetForm.ip_address}
              onChange={(e) => setAssetForm({ ...assetForm, ip_address: e.target.value })}
            />
            <select className="select" style={{ fontSize: 12, color: COMPROMISE_COLOR[assetForm.compromise_status] }} value={assetForm.compromise_status} onChange={(e) => setAssetForm({ ...assetForm, compromise_status: e.target.value })}>
              {COMPROMISE_STATUSES.map((s) => <option key={s} value={s}>{COMPROMISE_LABEL[s]}</option>)}
            </select>
            <button className="btn-primary" disabled={!assetForm.name.trim() || createAsset.isPending} onClick={() => createAsset.mutate()}>
              <Plus size={13} /> Add
            </button>
          </div>

          {(!assets || assets.length === 0) ? (
            <div className="empty-state"><HardDrive size={16} /><span>No assets tracked yet</span></div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {assets.map((a: any) => (
                <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', background: 'var(--raise)', borderRadius: 6 }}>
                  <HardDrive size={14} color="var(--text-3)" />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: 12, color: 'var(--text-1)' }}>
                      {a.name} <span style={{ color: 'var(--text-3)', fontWeight: 400 }}>· {ASSET_TYPE_LABEL[a.asset_type]}</span>
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--text-3)' }}>
                      {a.ip_address || 'No IP'}{a.description ? ` · ${a.description}` : ''}
                    </p>
                  </div>
                  <select
                    className="select"
                    style={{ fontSize: 10, padding: '2px 6px', color: COMPROMISE_COLOR[a.compromise_status] }}
                    value={a.compromise_status}
                    onChange={(e) => updateAsset.mutate({ assetId: a.id, data: { compromise_status: e.target.value } })}
                  >
                    {COMPROMISE_STATUSES.map((s) => <option key={s} value={s}>{COMPROMISE_LABEL[s]}</option>)}
                  </select>
                  <button className="btn-ghost" style={{ fontSize: 11, padding: '3px 6px' }} onClick={() => deleteAsset.mutate(a.id)}>
                    <Trash2 size={12} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </Section>
      )}

      {/* ── Evidence ── */}
      {tab === 'evidence' && (
        <Section title="Evidence register">
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
            <input
              className="input"
              style={{ flex: 1, minWidth: 160 }}
              placeholder="Filename / exhibit name"
              value={evidenceForm.filename}
              onChange={(e) => setEvidenceForm({ ...evidenceForm, filename: e.target.value })}
            />
            <input
              className="input"
              style={{ flex: 1, minWidth: 200 }}
              placeholder="SHA256 hash"
              value={evidenceForm.hash_sha256}
              onChange={(e) => setEvidenceForm({ ...evidenceForm, hash_sha256: e.target.value })}
            />
            <button className="btn-primary" disabled={!evidenceForm.filename.trim() || createEvidence.isPending} onClick={() => createEvidence.mutate()}>
              <Plus size={13} /> Add
            </button>
          </div>

          {(!evidenceList || evidenceList.length === 0) ? (
            <div className="empty-state"><Paperclip size={16} /><span>No evidence registered yet</span></div>
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <thead>
                  <tr><th>Filename</th><th>SHA256</th><th>Acquired by</th><th></th></tr>
                </thead>
                <tbody>
                  {evidenceList.map((ev: any) => (
                    <tr key={ev.id}>
                      <td style={{ fontSize: 12, color: 'var(--text-1)' }}>{ev.filename}</td>
                      <td style={{ fontSize: 11, fontFamily: 'JetBrains Mono,monospace', color: 'var(--text-2)' }}>{ev.hash_sha256 || '—'}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-3)' }}>{ev.acquired_by_name || '—'}</td>
                      <td style={{ textAlign: 'right' }}>
                        <button className="btn-ghost" style={{ fontSize: 11, padding: '3px 6px' }} onClick={() => deleteEvidence.mutate(ev.id)}>
                          <Trash2 size={12} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      )}

      {/* ── Tasks ── */}
      {tab === 'tasks' && (
        <Section title="Tasks">
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <input
              className="input"
              style={{ flex: 1 }}
              placeholder="New task…"
              value={taskForm.title}
              onChange={(e) => setTaskForm({ ...taskForm, title: e.target.value })}
              onKeyDown={(e) => e.key === 'Enter' && taskForm.title.trim() && createTask.mutate()}
            />
            <input
              type="date"
              className="input"
              style={{ width: 150 }}
              value={taskForm.due_date}
              onChange={(e) => setTaskForm({ ...taskForm, due_date: e.target.value })}
            />
            <button className="btn-primary" disabled={!taskForm.title.trim() || createTask.isPending} onClick={() => createTask.mutate()}>
              <Plus size={13} /> Add
            </button>
          </div>

          {(!tasks || tasks.length === 0) ? (
            <div className="empty-state"><ListChecks size={16} /><span>No tasks yet</span></div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {tasks.map((t: any) => {
                const done = t.status === 'done'
                return (
                  <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 10px', background: 'var(--raise)', borderRadius: 6 }}>
                    <button
                      className="btn-ghost"
                      style={{ padding: 2 }}
                      onClick={() => {
                        const next = TASK_STATUS_ORDER[(TASK_STATUS_ORDER.indexOf(t.status) + 1) % TASK_STATUS_ORDER.length]
                        updateTask.mutate({ taskId: t.id, data: { status: next } })
                      }}
                      title="Cycle status"
                    >
                      {done ? <CheckCircle2 size={15} color="#22c55e" /> : <Circle size={15} color="var(--text-3)" />}
                    </button>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <p style={{ fontSize: 12, color: done ? 'var(--text-3)' : 'var(--text-1)', textDecoration: done ? 'line-through' : 'none' }}>
                        {t.title}
                      </p>
                      <p style={{ fontSize: 10, color: 'var(--text-3)' }}>
                        {TASK_STATUS_LABEL[t.status]}
                        {t.assignee_name ? ` · ${t.assignee_name}` : ''}
                        {t.due_date ? ` · due ${formatDistanceToNow(new Date(t.due_date), { addSuffix: true })}` : ''}
                      </p>
                    </div>
                    <button className="btn-ghost" style={{ fontSize: 11, padding: '3px 6px' }} onClick={() => deleteTask.mutate(t.id)}>
                      <Trash2 size={12} />
                    </button>
                  </div>
                )
              })}
            </div>
          )}
        </Section>
      )}

      {/* ── Notes ── */}
      {tab === 'notes' && (
        <Section title="Investigation notes">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 16, padding: 12, background: 'var(--raise)', borderRadius: 6 }}>
            <input
              className="input"
              placeholder="Note title…"
              value={noteForm.title}
              onChange={(e) => setNoteForm({ ...noteForm, title: e.target.value })}
            />
            <textarea
              className="input"
              style={{ minHeight: 80, resize: 'vertical', fontFamily: 'inherit' }}
              placeholder="Write up findings, analysis, or investigation steps…"
              value={noteForm.content}
              onChange={(e) => setNoteForm({ ...noteForm, content: e.target.value })}
            />
            <button
              className="btn-primary"
              style={{ alignSelf: 'flex-end' }}
              disabled={!noteForm.title.trim() || !noteForm.content.trim() || createNote.isPending}
              onClick={() => createNote.mutate()}
            >
              <Plus size={13} /> Add note
            </button>
          </div>

          {(!notes || notes.length === 0) ? (
            <div className="empty-state"><StickyNote size={16} /><span>No notes yet</span></div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {notes.slice().reverse().map((n: any) => (
                <div key={n.id} style={{ padding: '10px 12px', background: 'var(--raise)', borderRadius: 6 }}>
                  {editingNoteId === n.id ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      <input
                        className="input"
                        value={editingNoteDraft.title}
                        onChange={(e) => setEditingNoteDraft({ ...editingNoteDraft, title: e.target.value })}
                      />
                      <textarea
                        className="input"
                        style={{ minHeight: 70, resize: 'vertical', fontFamily: 'inherit' }}
                        value={editingNoteDraft.content}
                        onChange={(e) => setEditingNoteDraft({ ...editingNoteDraft, content: e.target.value })}
                      />
                      <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                        <button className="btn-ghost" style={{ fontSize: 11 }} onClick={() => setEditingNoteId(null)}>Cancel</button>
                        <button
                          className="btn-primary"
                          style={{ fontSize: 11 }}
                          onClick={() => updateNote.mutate({ noteId: n.id, data: editingNoteDraft })}
                        >
                          Save
                        </button>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <StickyNote size={13} color="#a3e635" />
                        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>{n.title}</span>
                        <span style={{ fontSize: 10, color: 'var(--text-3)' }}>
                          {n.author_name || 'Analyst'} · {formatDistanceToNow(new Date(n.created_at), { addSuffix: true })}
                        </span>
                        <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
                          <button
                            className="btn-ghost"
                            style={{ fontSize: 11, padding: '3px 6px' }}
                            onClick={() => { setEditingNoteId(n.id); setEditingNoteDraft({ title: n.title, content: n.content }) }}
                          >
                            <Pencil size={11} />
                          </button>
                          <button className="btn-ghost" style={{ fontSize: 11, padding: '3px 6px' }} onClick={() => deleteNote.mutate(n.id)}>
                            <Trash2 size={11} />
                          </button>
                        </div>
                      </div>
                      <p style={{ fontSize: 12, color: 'var(--text-2)', whiteSpace: 'pre-wrap' }}>{n.content}</p>
                    </>
                  )}
                </div>
              ))}
            </div>
          )}
        </Section>
      )}

      {/* ── Comments ── */}
      {tab === 'comments' && (
        <Section title="Comments">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 16 }}>
            {(!comments || comments.length === 0) && (
              <div className="empty-state"><MessageSquare size={16} /><span>No comments yet</span></div>
            )}
            {(comments || []).map((cm: any) => (
              <div key={cm.id} style={{ padding: '10px 12px', background: 'var(--raise)', borderRadius: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-1)' }}>{cm.author_name || 'Analyst'}</span>
                  <span style={{ fontSize: 10, color: 'var(--text-3)' }}>{formatDistanceToNow(new Date(cm.created_at), { addSuffix: true })}</span>
                  {cm.is_internal && (
                    <span style={{ fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'rgba(168,85,247,0.12)', color: '#c084fc' }}>internal</span>
                  )}
                </div>
                <p style={{ fontSize: 12, color: 'var(--text-2)', whiteSpace: 'pre-wrap' }}>{cm.content}</p>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <textarea
              className="input"
              style={{ minHeight: 70, resize: 'vertical', fontFamily: 'inherit' }}
              placeholder={`Comment as ${fullName || 'you'}…`}
              value={commentDraft}
              onChange={(e) => setCommentDraft(e.target.value)}
            />
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: 'var(--text-3)' }}>
                <input type="checkbox" checked={commentInternal} onChange={(e) => setCommentInternal(e.target.checked)} />
                Internal only
              </label>
              <button
                className="btn-primary"
                style={{ marginLeft: 'auto' }}
                disabled={!commentDraft.trim() || addComment.isPending}
                onClick={() => addComment.mutate()}
              >
                <Send size={13} /> Post comment
              </button>
            </div>
          </div>
        </Section>
      )}
    </div>
  )
}

function MitreTagPicker({ options, selected, onChange }: { options: any[] | undefined; selected: string[]; onChange: (v: string[]) => void }) {
  const [query, setQuery] = useState('')
  const matches = query.trim()
    ? (options || [])
        .filter((t) => !selected.includes(t.id) && (t.id.toLowerCase().includes(query.toLowerCase()) || t.name.toLowerCase().includes(query.toLowerCase())))
        .slice(0, 6)
    : []

  return (
    <div>
      {selected.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 6 }}>
          {selected.map((tid) => {
            const t = (options || []).find((o) => o.id === tid)
            return (
              <span key={tid} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 10, padding: '2px 6px', borderRadius: 3, background: 'rgba(196,132,252,0.12)', color: '#c084fc' }}>
                <Target size={9} /> {tid}{t ? ` · ${t.name}` : ''}
                <button
                  type="button"
                  onClick={() => onChange(selected.filter((s) => s !== tid))}
                  style={{ border: 'none', background: 'none', cursor: 'pointer', color: 'inherit', padding: 0, display: 'flex' }}
                >
                  <X size={9} />
                </button>
              </span>
            )
          })}
        </div>
      )}
      <div style={{ position: 'relative' }}>
        <input
          className="input"
          style={{ fontSize: 11, padding: '4px 8px', width: '100%' }}
          placeholder="Tag MITRE ATT&CK technique… (e.g. T1059)"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {matches.length > 0 && (
          <div style={{ position: 'absolute', zIndex: 5, top: '100%', left: 0, right: 0, marginTop: 2, background: 'var(--raise)', border: '1px solid var(--line)', borderRadius: 6, overflow: 'hidden' }}>
            {matches.map((t) => (
              <div
                key={t.id}
                onClick={() => { onChange([...selected, t.id]); setQuery('') }}
                style={{ padding: '6px 10px', fontSize: 11, cursor: 'pointer', color: 'var(--text-1)' }}
              >
                <b>{t.id}</b> — {t.name} <span style={{ color: 'var(--text-3)' }}>({t.tactic})</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-3)', marginBottom: 4 }}>
        {label}
      </p>
      {children}
    </div>
  )
}
