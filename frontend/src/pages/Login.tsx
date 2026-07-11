import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Mail, Lock, Loader2, ArrowRight, ShieldCheck, KeyRound, ArrowLeft } from 'lucide-react'
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
  const [mfaToken, setMfaToken] = useState<string | null>(null)
  const [code, setCode]         = useState('')

  function finishLogin(data: any) {
    setAuth(data.access_token, data.user_id, data.role, data.full_name || email)
    toast.success('Authenticated')
    navigate('/dashboard')
  }

  function loginErrorMessage(err: any): string {
    if (err?.code === 'ECONNABORTED') {
      return 'Server did not respond within 15 seconds — it may still be starting up, try again shortly'
    }
    if (!err?.response) {
      return 'Cannot reach the server — check that the backend is running and try again'
    }
    const { status, data } = err.response
    // FastAPI puts human-readable errors in `detail`; on 422 it's an array
    // of field errors instead, handled by the status branches below.
    const detail = typeof data?.detail === 'string' ? data.detail : ''
    if (status === 401) {
      const hint = email.includes('@') ? '' : ' — sign in with your full email address'
      return (detail || 'Incorrect email or password') + hint
    }
    if (detail) return detail
    if (status === 422) return 'Enter both your email address and password'
    if (status === 429) return 'Too many attempts — wait a few minutes and try again'
    if (status >= 500) return `Server error (HTTP ${status}) — try again or check the backend logs`
    return `Sign-in failed (HTTP ${status})`
  }

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      const { data } = await api.login(email, password)
      if (data.mfa_required) {
        setMfaToken(data.mfa_token)
        setCode('')
      } else {
        finishLogin(data)
      }
    } catch (err: any) {
      toast.error(loginErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  async function handleMfaVerify(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      const { data } = await api.mfaVerify(mfaToken!, code)
      finishLogin(data)
    } catch (err: any) {
      const detail = err?.response?.data?.detail || ''
      if (detail.includes('sign in again')) {
        toast.error('Session expired — sign in again')
        setMfaToken(null)
      } else {
        toast.error(detail || 'Invalid verification code')
      }
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
          <img
            src="/logo.png"
            alt="SocBlitz"
            style={{
              width: 36, height: 36,
              borderRadius: 8,
              boxShadow: '0 0 16px rgba(37,99,235,0.4)',
            }}
          />
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
            <img
              src="/logo.png"
              alt="SocBlitz"
              style={{ width: 32, height: 32, borderRadius: 7 }}
            />
            <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-1)' }}>SocBlitz</span>
          </div>

          {mfaToken ? (
            <>
              <div
                className="flex items-center justify-center"
                style={{
                  width: 44, height: 44, borderRadius: 10, marginBottom: 18,
                  background: 'rgba(37,99,235,0.12)', border: '1px solid rgba(37,99,235,0.25)',
                }}
              >
                <ShieldCheck size={20} color="#60a5fa" />
              </div>
              <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--text-1)', letterSpacing: '-0.02em', marginBottom: 6 }}>
                Two-factor authentication
              </h1>
              <p style={{ fontSize: 13, color: 'var(--text-3)', marginBottom: 28 }}>
                Enter the 6-digit code from your authenticator app, or a backup code
              </p>

              <form onSubmit={handleMfaVerify} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <div>
                  <label style={{ display: 'block', fontSize: 12, fontWeight: 500, color: 'var(--text-3)', marginBottom: 6 }}>
                    Verification code
                  </label>
                  <div style={{ position: 'relative' }}>
                    <KeyRound size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
                    <input
                      className="input"
                      style={{ paddingLeft: 36, fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.15em' }}
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      placeholder="123456"
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                      required
                      autoFocus
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading || !code.trim()}
                  className="btn-primary"
                  style={{ width: '100%', justifyContent: 'center', padding: '10px 16px', marginTop: 6, fontSize: 14 }}
                >
                  {loading ? (
                    <><Loader2 size={15} className="animate-spin" /> Verifying…</>
                  ) : (
                    <>Verify <ArrowRight size={15} /></>
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => { setMfaToken(null); setCode('') }}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                    fontSize: 12, color: 'var(--text-3)', background: 'none', border: 'none',
                    cursor: 'pointer', padding: '6px 0',
                  }}
                >
                  <ArrowLeft size={12} /> Back to sign in
                </button>
              </form>
            </>
          ) : (
            <>
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
            </>
          )}

          {!mfaToken && (
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
              <strong style={{ color: 'var(--text-2)' }}>First sign-in</strong><br />
              Use the admin email and password set via <code>FIRST_ADMIN_EMAIL</code> / <code>FIRST_ADMIN_PASSWORD</code> in your deployment&rsquo;s <code>.env</code>.
            </div>
          )}

          <p style={{ marginTop: 20, textAlign: 'center', fontSize: 11, color: 'var(--text-3)' }}>
            SocBlitz v1.0.0 · Open-source SOC platform
          </p>
        </div>
      </div>
    </div>
  )
}
