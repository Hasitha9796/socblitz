import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  User, Mail, ShieldCheck, ShieldOff, Building2, Users, Plus,
  RotateCcw, Activity, Loader2, ChevronRight, Lock,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api, useAuthStore } from '../stores/auth'

const ROLE_COLORS: Record<string, string> = {
  admin:         '#f87171',
  analyst:       '#60a5fa',
  customer_user: '#a78bfa',
  viewer:        '#94a3b8',
}

function RoleBadge({ role }: { role: string }) {
  const color = ROLE_COLORS[role] || '#94a3b8'
  return (
    <span
      style={{
        fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em',
        padding: '2px 8px', borderRadius: 999,
        color, background: `${color}1f`, border: `1px solid ${color}44`,
      }}
    >
      {role.replace('_', ' ')}
    </span>
  )
}

export default function Settings() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const role = useAuthStore((s) => s.role)
  const isAdmin = role === 'admin'

  const { data: me } = useQuery({ queryKey: ['me'], queryFn: () => api.me().then((r) => r.data) })
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: () => api.health().then((r) => r.data),
    refetchInterval: 30_000,
  })
  const { data: users } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.listUsers().then((r) => r.data),
    enabled: isAdmin,
  })
  const { data: tenants } = useQuery({
    queryKey: ['tenants'],
    queryFn: () => api.listTenants().then((r) => r.data),
    enabled: isAdmin,
  })

  // ── New-user form state ──
  const [showUserForm, setShowUserForm] = useState(false)
  const [newUser, setNewUser] = useState({ email: '', password: '', full_name: '', role: 'analyst' })

  const createUser = useMutation({
    mutationFn: () => api.createUser(newUser),
    onSuccess: () => {
      toast.success('User created')
      setNewUser({ email: '', password: '', full_name: '', role: 'analyst' })
      setShowUserForm(false)
      qc.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Failed to create user'),
  })

  const resetMfa = useMutation({
    mutationFn: (id: string) => api.mfaResetUser(id),
    onSuccess: () => {
      toast.success('MFA reset — user can re-enroll at next sign-in')
      qc.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Failed to reset MFA'),
  })

  // ── New-tenant form state ──
  const [showTenantForm, setShowTenantForm] = useState(false)
  const [newTenant, setNewTenant] = useState({ code: '', name: '', description: '' })

  const createTenant = useMutation({
    mutationFn: () => api.createTenant(newTenant),
    onSuccess: () => {
      toast.success('Organization created')
      setNewTenant({ code: '', name: '', description: '' })
      setShowTenantForm(false)
      qc.invalidateQueries({ queryKey: ['tenants'] })
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail || 'Failed to create organization'),
  })

  const userList = users || []
  const tenantList = tenants || []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 860 }}>

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-sub">Profile, team access, organizations, and system status</p>
        </div>
      </div>

      {/* ── Profile ── */}
      <div className="card" style={{ padding: '18px 20px' }}>
        <p style={sectionLabel}>Profile</p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginTop: 12 }}>
          <div
            className="flex items-center justify-center rounded-full shrink-0"
            style={{ width: 44, height: 44, background: 'rgba(37,99,235,0.18)' }}
          >
            <User size={20} color="#60a5fa" />
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)' }}>
                {me?.full_name || 'Analyst'}
              </p>
              {me?.role && <RoleBadge role={me.role} />}
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-3)', display: 'flex', alignItems: 'center', gap: 5, marginTop: 2 }}>
              <Mail size={11} /> {me?.email}
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            {me?.mfa_enabled
              ? <span style={{ fontSize: 12, color: '#22c55e', display: 'flex', alignItems: 'center', gap: 5 }}><ShieldCheck size={13} /> 2FA on</span>
              : <span style={{ fontSize: 12, color: '#f87171', display: 'flex', alignItems: 'center', gap: 5 }}><ShieldOff size={13} /> 2FA off</span>}
          </div>
        </div>

        <button
          className="btn-secondary"
          style={{ marginTop: 14, fontSize: 12 }}
          onClick={() => navigate('/account')}
        >
          <Lock size={12} /> Manage account security
          <ChevronRight size={12} />
        </button>
      </div>

      {/* ── Team members (admin) ── */}
      {isAdmin && (
        <div className="card" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <p style={sectionLabel}><Users size={12} style={{ display: 'inline', marginRight: 6, verticalAlign: '-1px' }} />Team members ({userList.length})</p>
            <button className="btn-primary" style={{ fontSize: 11, padding: '5px 12px' }} onClick={() => setShowUserForm((v) => !v)}>
              <Plus size={12} /> Add user
            </button>
          </div>

          {showUserForm && (
            <form
              onSubmit={(e) => { e.preventDefault(); createUser.mutate() }}
              style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 14, padding: 14, borderRadius: 8, background: 'rgba(96,130,182,0.06)', border: '1px solid var(--line)' }}
            >
              <input className="input" placeholder="Full name" value={newUser.full_name}
                onChange={(e) => setNewUser({ ...newUser, full_name: e.target.value })} />
              <input className="input" type="email" placeholder="Email" required value={newUser.email}
                onChange={(e) => setNewUser({ ...newUser, email: e.target.value })} />
              <input className="input" type="password" placeholder="Temporary password" required value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
              <select className="input" value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}>
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="customer_user">Customer user</option>
                <option value="viewer">Viewer</option>
              </select>
              <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button type="button" className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setShowUserForm(false)}>Cancel</button>
                <button type="submit" className="btn-primary" style={{ fontSize: 12 }} disabled={createUser.isPending}>
                  {createUser.isPending ? <Loader2 size={13} className="animate-spin" /> : 'Create user'}
                </button>
              </div>
            </form>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 12 }}>
            {userList.map((u: any) => (
              <div key={u.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 12px', borderRadius: 8, background: 'rgba(11,16,26,0.4)', border: '1px solid var(--line)' }}>
                <div className="flex items-center justify-center rounded-full shrink-0" style={{ width: 30, height: 30, background: 'rgba(96,130,182,0.1)' }}>
                  <User size={14} color="var(--text-3)" />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {u.full_name || u.email}{!u.is_active && <span style={{ color: '#f87171', fontSize: 11, marginLeft: 6 }}>(disabled)</span>}
                  </p>
                  <p style={{ fontSize: 11, color: 'var(--text-3)' }}>{u.email}</p>
                </div>
                {u.mfa_enabled
                  ? <ShieldCheck size={14} color="#22c55e" />
                  : <ShieldOff size={14} color="var(--text-3)" />}
                <RoleBadge role={u.role} />
                {u.mfa_enabled && u.id !== me?.id && (
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 11, padding: '4px 10px' }}
                    title="Reset this user's MFA"
                    disabled={resetMfa.isPending}
                    onClick={() => { if (confirm(`Reset MFA for ${u.email}?`)) resetMfa.mutate(u.id) }}
                  >
                    <RotateCcw size={11} /> Reset MFA
                  </button>
                )}
              </div>
            ))}
            {userList.length === 0 && <p style={{ fontSize: 12, color: 'var(--text-3)' }}>No users yet.</p>}
          </div>
        </div>
      )}

      {/* ── Organizations / Tenants (admin) ── */}
      {isAdmin && (
        <div className="card" style={{ padding: '18px 20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <p style={sectionLabel}><Building2 size={12} style={{ display: 'inline', marginRight: 6, verticalAlign: '-1px' }} />Organizations ({tenantList.length})</p>
            <button className="btn-primary" style={{ fontSize: 11, padding: '5px 12px' }} onClick={() => setShowTenantForm((v) => !v)}>
              <Plus size={12} /> Add organization
            </button>
          </div>

          {showTenantForm && (
            <form
              onSubmit={(e) => { e.preventDefault(); createTenant.mutate() }}
              style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 14, padding: 14, borderRadius: 8, background: 'rgba(96,130,182,0.06)', border: '1px solid var(--line)' }}
            >
              <input className="input" placeholder="Code (e.g. acme)" required value={newTenant.code}
                onChange={(e) => setNewTenant({ ...newTenant, code: e.target.value })} />
              <input className="input" placeholder="Name" required value={newTenant.name}
                onChange={(e) => setNewTenant({ ...newTenant, name: e.target.value })} />
              <input className="input" style={{ gridColumn: '1 / -1' }} placeholder="Description (optional)" value={newTenant.description}
                onChange={(e) => setNewTenant({ ...newTenant, description: e.target.value })} />
              <div style={{ gridColumn: '1 / -1', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button type="button" className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setShowTenantForm(false)}>Cancel</button>
                <button type="submit" className="btn-primary" style={{ fontSize: 12 }} disabled={createTenant.isPending}>
                  {createTenant.isPending ? <Loader2 size={13} className="animate-spin" /> : 'Create'}
                </button>
              </div>
            </form>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 12 }}>
            {tenantList.map((t: any) => (
              <div key={t.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 12px', borderRadius: 8, background: 'rgba(11,16,26,0.4)', border: '1px solid var(--line)' }}>
                <Building2 size={15} color="#60a5fa" style={{ flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-1)' }}>{t.name}</p>
                  <p style={{ fontSize: 11, color: 'var(--text-3)' }}>{t.description || t.code}</p>
                </div>
                <code style={{ fontSize: 11, color: 'var(--text-3)', fontFamily: "'JetBrains Mono', monospace" }}>{t.code}</code>
              </div>
            ))}
            {tenantList.length === 0 && <p style={{ fontSize: 12, color: 'var(--text-3)' }}>No organizations yet.</p>}
          </div>
        </div>
      )}

      {/* ── System status ── */}
      <div className="card" style={{ padding: '18px 20px' }}>
        <p style={sectionLabel}><Activity size={12} style={{ display: 'inline', marginRight: 6, verticalAlign: '-1px' }} />System status</p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12 }}>
          <span
            style={{
              width: 9, height: 9, borderRadius: '50%',
              background: health?.status === 'ok' ? '#22c55e' : '#f59e0b',
              boxShadow: health?.status === 'ok' ? '0 0 6px rgba(34,197,94,0.5)' : 'none',
            }}
          />
          <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-1)', textTransform: 'capitalize' }}>
            {health?.status || 'checking…'}
          </span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 8, marginTop: 12 }}>
          {Object.entries(health?.checks || {}).map(([name, state]) => {
            const ok = state === 'ok'
            return (
              <div key={name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', borderRadius: 8, background: 'rgba(11,16,26,0.4)', border: '1px solid var(--line)' }}>
                <span style={{ fontSize: 12, color: 'var(--text-2)', textTransform: 'capitalize' }}>{name}</span>
                <span style={{ fontSize: 11, fontWeight: 600, color: ok ? '#22c55e' : '#f87171' }}>{ok ? 'OK' : 'Error'}</span>
              </div>
            )
          })}
        </div>
      </div>

    </div>
  )
}

const sectionLabel: React.CSSProperties = {
  fontSize: 11, fontWeight: 700, textTransform: 'uppercase',
  letterSpacing: '0.08em', color: 'var(--text-3)',
}
