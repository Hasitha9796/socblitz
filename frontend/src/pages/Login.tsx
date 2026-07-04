import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Zap, Mail, Lock, Loader2, ArrowRight } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuthStore, api } from '../stores/auth'

// Minimal threat-feed decoration — static, no random() so no hydration mismatch
const FEED_LINES = [
  { sev: 'critical', text: 'Lateral movement detected — DC01', time: '00:03' },
  { sev: 'high',     text: 'Brute force: 412 attempts on sshd', time: '00:07' },
  { sev: 'medium',   text: 'DNS over HTTPS traffic anomaly',    time: '00:11' },
  { sev: 'critical', text: 'Credential dump: lsass.exe access', time: '00:18' },
  { sev: 'high',     text: 'C2 beacon to 185.220.101.42:443',   time: '00:22' },
  { sev: 'medium',   text: 'New scheduled task via GPO',        time: '00:29' },
  { sev: 'low',      text: 'Port scan from 10.0.0.44',          time: '00:35' },
  { sev: 'critical', text: 'Ransomware extension pattern: .enc', time: '00:41' },
  { sev: 'high',     text: 'Mimikatz signature in memory',       time: '00:48' },
  { sev: 'medium',   text: 'PowerShell obfuscation detected',    time: '00:54' },
  { sev: 'low',      text: 'RDP connection from 192.168.2.19',   time: '01:02' },
  { sev: 'high',     text: 'Exfil: 1.4 GB to external FTP',     time: '01:09' },
]

const SEV_COLOR: Record<string, string> = {
  critical: '#f43f5e',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#67e8f9',
}

export default function Login() {
  const navigate   = useNavigate()
  const setAuth    = useAuthStore((s) => s.setAuth)
  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading]   = useState(false)

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      const { data } = await api.login(email, password)
      setAuth(data.access_token, data.user_id, data.role, data.full_name || email)
      toast.success('Authenticated')
      navigate('/dashboard')
    } catch {
      toast.error('Invalid credentials')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      className="min-h-screen flex"
      style={{ background: 'var(--void)', fontFamily: "'Inter', system-ui, sans-serif" }}
    >
      {/* ── Left panel — threat feed ─────────────────────────────────── */}
      <div
        className="hidden lg:flex flex-col justify-between flex-1"
        style={{
          background: 'var(--base)',
          borderRight: '1px solid var(--line)',
          padding: '48px 40px',
          maxWidth: 480,
        }}
      >
        {/* Brand mark */}
        <div className="flex items-center gap-3">
          <div
            style={{
              width: 36, height: 36,
              background: 'linear-gradient(135deg, #1d4ed8, #2563eb)',
              borderRadius: 8,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 16px rgba(37,99,235,0.4)',
            }}
          >
            <Zap size={18} color="#fff" strokeWidth={2.5} />
          </div>
          <div>
            <p style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-1)', letterSpacing: '-0.01em' }}>SocBlitz</p>
            <p style={{ fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Security Operations</p>
          </div>
        </div>

        {/* Live feed */}
        <div style={{ flex: 1, margin: '48px 0 32px' }}>
          <div
            style={{
              fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
              letterSpacing: '0.1em', color: 'var(--text-3)', marginBottom: 16,
              display: 'flex', alignItems: 'center', gap: 8,
            }}
          >
            <span
              style={{
                display: 'inline-block', width: 6, height: 6, borderRadius: '50%',
                background: '#22c55e', boxShadow: '0 0 8px rgba(34,197,94,0.6)',
              }}
            />
            Live threat feed
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 1, overflow: 'hidden', maxHeight: 380 }}>
            {FEED_LINES.map((line, i) => (
              <div
                key={i}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '7px 10px',
                  borderRadius: 4,
                  background: i % 2 === 0 ? 'transparent' : 'rgba(96,130,182,0.03)',
                  opacity: 1 - (i * 0.05),
                }}
              >
                <span
                  style={{
                    width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                    background: SEV_COLOR[line.sev] || '#64748b',
                    boxShadow: line.sev === 'critical' ? `0 0 6px ${SEV_COLOR[line.sev]}` : 'none',
                  }}
                />
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 11, color: 'var(--text-3)', flexShrink: 0, width: 32,
                }}>
                  {line.time}
                </span>
                <span style={{ fontSize: 12, color: 'var(--text-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {line.text}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <p style={{ fontSize: 11, color: 'var(--text-3)', lineHeight: 1.6 }}>
          Unified SIEM, SOAR, and threat intelligence.<br />
          Built for teams that move at alert speed.
        </p>
      </div>

      {/* ── Right panel — login form ──────────────────────────────────── */}
      <div className="flex flex-1 items-center justify-center p-8">
        <div style={{ width: '100%', maxWidth: 360 }} className="animate-slide-up">

          {/* Mobile brand */}
          <div className="lg:hidden flex items-center gap-2 mb-8">
            <div
              style={{
                width: 32, height: 32,
                background: 'linear-gradient(135deg, #1d4ed8, #2563eb)',
                borderRadius: 7,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}
            >
              <Zap size={16} color="#fff" strokeWidth={2.5} />
            </div>
            <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-1)' }}>SocBlitz</span>
          </div>

          <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-1)', letterSpacing: '-0.02em', marginBottom: 6 }}>
            Sign in
          </h1>
          <p style={{ fontSize: 13, color: 'var(--text-3)', marginBottom: 28 }}>
            Access your security operations centre
          </p>

          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 500, color: 'var(--text-3)', marginBottom: 6 }}>
                Email address
              </label>
              <div style={{ position: 'relative' }}>
                <Mail size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
                <input
                  className="input"
                  style={{ paddingLeft: 36 }}
                  type="email"
                  placeholder="analyst@yourorg.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  autoFocus
                />
              </div>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 500, color: 'var(--text-3)', marginBottom: 6 }}>
                Password
              </label>
              <div style={{ position: 'relative' }}>
                <Lock size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
                <input
                  className="input"
                  style={{ paddingLeft: 36 }}
                  type="password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ width: '100%', justifyContent: 'center', padding: '10px 16px', marginTop: 6, fontSize: 14 }}
            >
              {loading ? (
                <><Loader2 size={15} className="animate-spin" /> Authenticating…</>
              ) : (
                <>Sign in <ArrowRight size={15} /></>
              )}
            </button>
          </form>

          <div
            style={{
              marginTop: 24,
              padding: '12px 14px',
              background: 'rgba(37,99,235,0.06)',
              border: '1px solid rgba(37,99,235,0.15)',
              borderRadius: 6,
              fontSize: 11,
              color: 'var(--text-3)',
              lineHeight: 1.6,
            }}
          >
            <strong style={{ color: 'var(--text-2)' }}>Default credentials</strong><br />
            admin@socblitz.local / SocBlitz@Admin1!
          </div>

          <p style={{ marginTop: 20, textAlign: 'center', fontSize: 11, color: 'var(--text-3)' }}>
            SocBlitz v1.0.0 · Open-source SOC platform
          </p>
        </div>
      </div>
    </div>
  )
}
