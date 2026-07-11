import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import {
  LayoutDashboard, Bell, FolderOpen, Monitor, Shield, Workflow,
  Plug, Settings, LogOut, ChevronLeft, ChevronRight, User,
  AlertTriangle, Activity, Sparkles, Fingerprint
} from 'lucide-react'
import { useAuthStore } from '../stores/auth'
import { useQuery } from '@tanstack/react-query'
import { api } from '../stores/auth'
import clsx from 'clsx'

const NAV_GROUPS = [
  {
    label: 'Monitor',
    items: [
      { to: '/dashboard',    icon: LayoutDashboard, label: 'Overview'      },
      { to: '/alerts',       icon: Bell,            label: 'Alerts'        },
      { to: '/events',       icon: Activity,        label: 'Events'        },
      { to: '/agents',       icon: Monitor,         label: 'Agents'        },
      { to: '/custom-dashboard', icon: Sparkles,    label: 'Dashboard' },
    ],
  },
  {
    label: 'Investigate',
    items: [
      { to: '/cases',        icon: FolderOpen,      label: 'Cases'         },
      { to: '/threat-intel', icon: Shield,          label: 'Threat Intel'  },
      { to: '/forensics',    icon: Fingerprint,     label: 'Forensics'     },
      { to: '/soar',         icon: Workflow,        label: 'SOAR'          },
    ],
  },
  {
    label: 'Platform',
    items: [
      { to: '/connectors',   icon: Plug,            label: 'Connectors'   },
      { to: '/settings',     icon: Settings,        label: 'Settings'     },
    ],
  },
]

function LiveClock() {
  const [time, setTime] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000)
    return () => clearInterval(t)
  }, [])
  return (
    <span className="tabular font-mono text-xs text-3">
      {time.toUTCString().slice(17, 25)} UTC
    </span>
  )
}

export default function DashboardLayout() {
  const location  = useLocation()
  const navigate  = useNavigate()
  const clearAuth = useAuthStore((s) => s.clearAuth)
  const fullName  = useAuthStore((s) => s.fullName)
  const role      = useAuthStore((s) => s.role)
  const [open, setOpen] = useState(true)

  const { data: alertStats } = useQuery({
    queryKey: ['alert-stats'],
    queryFn: () => api.alertStats().then((r) => r.data),
    refetchInterval: 30_000,
  })

  const criticalCount = alertStats?.severity?.critical ?? 0
  const newCount = alertStats?.status?.new ?? 0

  const currentPage = NAV_GROUPS
    .flatMap((g) => g.items)
    .find((item) => location.pathname.startsWith(item.to))

  function handleLogout() {
    clearAuth()
    navigate('/login')
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'var(--void)' }}>

      {/* ── Sidebar ─────────────────────────────────────────────────── */}
      <aside
        className={clsx(
          'flex flex-col shrink-0 transition-all duration-200',
          'border-r',
          open ? 'w-[220px]' : 'w-[56px]'
        )}
        style={{ background: 'var(--base)', borderColor: 'var(--line)' }}
      >
        {/* Brand */}
        <div
          className={clsx(
            'flex items-center border-b shrink-0',
            open ? 'gap-3 px-4 py-3.5' : 'justify-center px-2 py-3.5'
          )}
          style={{ borderColor: 'var(--line)' }}
        >
          <img
            src="/logo.png"
            alt="SocBlitz"
            className="rounded shrink-0"
            style={{
              width: 30, height: 30,
              boxShadow: '0 0 12px rgba(37,99,235,0.4)',
            }}
          />
          {open && (
            <div className="flex-1 min-w-0">
              <p style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-1)', letterSpacing: '-0.01em' }}>
                SocBlitz
              </p>
              <p style={{ fontSize: 10, color: 'var(--text-3)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                SOC Platform
              </p>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-2">
          {NAV_GROUPS.map((group) => (
            <div key={group.label}>
              {open && <p className="nav-section-label">{group.label}</p>}
              {!open && <div style={{ height: 10 }} />}
              {group.items.map(({ to, icon: Icon, label }) => {
                const active = location.pathname.startsWith(to)
                return (
                  <button
                    key={to}
                    onClick={() => navigate(to)}
                    className={clsx('nav-item w-full', active && 'active')}
                    style={open ? {} : { margin: '2px 6px', padding: '8px 0', justifyContent: 'center', width: 'calc(100% - 12px)' }}
                    title={!open ? label : undefined}
                  >
                    <Icon size={15} style={{ flexShrink: 0, opacity: active ? 1 : 0.7 }} />
                    {open && <span style={{ flex: 1, textAlign: 'left' }}>{label}</span>}
                    {open && active && (
                      <span
                        style={{
                          width: 5, height: 5, borderRadius: '50%',
                          background: '#60a5fa', flexShrink: 0,
                        }}
                      />
                    )}
                  </button>
                )
              })}
            </div>
          ))}
        </nav>

        {/* User / collapse */}
        <div style={{ borderTop: '1px solid var(--line)', padding: '10px 8px' }}>
          {open ? (
            <div className="flex items-center gap-2.5 px-2 py-1.5 rounded" style={{ background: 'rgba(96,130,182,0.06)' }}>
              <button
                onClick={() => navigate('/account')}
                className="flex items-center gap-2.5 flex-1 min-w-0"
                style={{ textAlign: 'left' }}
                title="Account security"
              >
                <div
                  className="flex items-center justify-center rounded-full shrink-0"
                  style={{ width: 28, height: 28, background: 'rgba(37,99,235,0.2)' }}
                >
                  <User size={13} color="#60a5fa" />
                </div>
                <div className="flex-1 min-w-0">
                  <p style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {fullName || 'Analyst'}
                  </p>
                  <p style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'capitalize' }}>{role}</p>
                </div>
              </button>
              <button
                onClick={handleLogout}
                style={{ color: 'var(--text-3)', transition: 'color 0.12s' }}
                title="Sign out"
                onMouseEnter={(e) => e.currentTarget.style.color = '#f43f5e'}
                onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-3)'}
              >
                <LogOut size={13} />
              </button>
            </div>
          ) : (
            <button
              onClick={handleLogout}
              className="nav-item w-full"
              style={{ margin: '0 2px', padding: '8px', justifyContent: 'center', width: 'calc(100% - 4px)' }}
              title="Sign out"
            >
              <LogOut size={14} />
            </button>
          )}
          <button
            onClick={() => setOpen((v) => !v)}
            className="w-full flex items-center justify-center mt-2 rounded"
            style={{
              padding: '5px',
              color: 'var(--text-3)',
              transition: 'background 0.12s, color 0.12s',
            }}
            onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(96,130,182,0.08)'; e.currentTarget.style.color = 'var(--text-2)' }}
            onMouseLeave={(e) => { e.currentTarget.style.background = ''; e.currentTarget.style.color = 'var(--text-3)' }}
          >
            {open
              ? <ChevronLeft size={14} />
              : <ChevronRight size={14} />
            }
          </button>
        </div>
      </aside>

      {/* ── Main ─────────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <header
          className="shrink-0 flex items-center gap-4 px-5"
          style={{
            height: 48,
            borderBottom: '1px solid var(--line)',
            background: 'rgba(12,18,32,0.8)',
            backdropFilter: 'blur(12px)',
          }}
        >
          {/* Page title */}
          <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-2)', letterSpacing: '0.01em' }}>
            {currentPage?.label ?? 'Dashboard'}
          </div>

          <div className="flex-1" />

          {/* Live clock */}
          <LiveClock />

          {/* Critical alert count */}
          {criticalCount > 0 && (
            <button
              onClick={() => navigate('/alerts')}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded"
              style={{
                background: 'rgba(244,63,94,0.12)',
                border: '1px solid rgba(244,63,94,0.25)',
                color: '#f87171',
                fontSize: 12,
                fontWeight: 500,
              }}
            >
              <AlertTriangle size={12} />
              <span className="tabular">{criticalCount} critical</span>
            </button>
          )}

          {/* Pulse indicator */}
          <div className="flex items-center gap-1.5">
            <div className="relative flex h-2 w-2">
              <span
                className="animate-ping-slow absolute inline-flex h-full w-full rounded-full opacity-60"
                style={{ background: '#22c55e' }}
              />
              <span
                className="relative inline-flex rounded-full h-2 w-2"
                style={{ background: '#22c55e', boxShadow: '0 0 6px rgba(34,197,94,0.6)' }}
              />
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-3)' }}>Live</span>
          </div>
        </header>

        {/* Content */}
        <main
          className="flex-1 overflow-y-auto animate-fade-in"
          style={{ padding: '22px 24px' }}
        >
          <Outlet />
        </main>
      </div>
    </div>
  )
}
