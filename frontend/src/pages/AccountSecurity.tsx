import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ShieldCheck, ShieldOff, Smartphone, KeyRound, Lock, Loader2,
  Copy, Check, AlertTriangle,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { api } from '../stores/auth'

interface SetupData {
  secret: string
  otpauth_uri: string
  qr_code: string
}

export default function AccountSecurity() {
  const queryClient = useQueryClient()
  const { data: me, isLoading } = useQuery({
    queryKey: ['me'],
    queryFn: () => api.me().then((r) => r.data),
  })

  const [setup, setSetup]             = useState<SetupData | null>(null)
  const [enableCode, setEnableCode]   = useState('')
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null)
  const [disablePassword, setDisablePassword] = useState('')
  const [disableCode, setDisableCode] = useState('')
  const [busy, setBusy]               = useState(false)
  const [copied, setCopied]           = useState(false)

  async function startSetup() {
    setBusy(true)
    try {
      const { data } = await api.mfaSetup()
      setSetup(data)
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Could not start MFA setup')
    } finally {
      setBusy(false)
    }
  }

  async function confirmEnable(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    try {
      const { data } = await api.mfaEnable(enableCode)
      setBackupCodes(data.backup_codes)
      setSetup(null)
      setEnableCode('')
      queryClient.invalidateQueries({ queryKey: ['me'] })
      toast.success('Two-factor authentication enabled')
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Invalid verification code')
    } finally {
      setBusy(false)
    }
  }

  async function handleDisable(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    try {
      await api.mfaDisable(disablePassword, disableCode)
      setDisablePassword('')
      setDisableCode('')
      setBackupCodes(null)
      queryClient.invalidateQueries({ queryKey: ['me'] })
      toast.success('Two-factor authentication disabled')
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Could not disable MFA')
    } finally {
      setBusy(false)
    }
  }

  function copyBackupCodes() {
    if (!backupCodes) return
    navigator.clipboard.writeText(backupCodes.join('\n'))
    setCopied(true)
    toast.success('Backup codes copied')
    setTimeout(() => setCopied(false), 2000)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center" style={{ height: 240 }}>
        <Loader2 size={20} className="animate-spin" style={{ color: 'var(--text-3)' }} />
      </div>
    )
  }

  const mfaEnabled = !!me?.mfa_enabled

  return (
    <div style={{ maxWidth: 640 }}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Account security</h1>
          <p className="page-sub">Two-factor authentication for {me?.email}</p>
        </div>
      </div>

      {/* ── Status ─────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: '18px 20px', marginBottom: 16 }}>
        <div className="flex items-center gap-3">
          <div
            className="flex items-center justify-center rounded shrink-0"
            style={{
              width: 38, height: 38,
              background: mfaEnabled ? 'rgba(34,197,94,0.12)' : 'rgba(244,63,94,0.10)',
              border: `1px solid ${mfaEnabled ? 'rgba(34,197,94,0.3)' : 'rgba(244,63,94,0.25)'}`,
            }}
          >
            {mfaEnabled
              ? <ShieldCheck size={18} color="#22c55e" />
              : <ShieldOff size={18} color="#f87171" />}
          </div>
          <div className="flex-1">
            <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)' }}>
              Two-factor authentication is {mfaEnabled ? 'enabled' : 'off'}
            </p>
            <p style={{ fontSize: 12, color: 'var(--text-3)' }}>
              {mfaEnabled
                ? 'Signing in requires a code from your authenticator app.'
                : 'Add a second step at sign-in using a TOTP authenticator app.'}
            </p>
          </div>
          {!mfaEnabled && !setup && (
            <button className="btn-primary" onClick={startSetup} disabled={busy} style={{ fontSize: 13 }}>
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Smartphone size={14} />}
              Enable
            </button>
          )}
        </div>
      </div>

      {/* ── Enrollment: scan QR + confirm code ─────────────────────── */}
      {setup && (
        <div className="card" style={{ padding: '20px', marginBottom: 16 }}>
          <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', marginBottom: 4 }}>
            1 · Scan this QR code
          </p>
          <p style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 14 }}>
            Use Google Authenticator, Authy, 1Password, or any TOTP app.
          </p>

          <div className="flex gap-5 items-start" style={{ flexWrap: 'wrap' }}>
            <img
              src={setup.qr_code}
              alt="TOTP QR code"
              style={{ width: 168, height: 168, borderRadius: 8, background: '#fff', padding: 8 }}
            />
            <div style={{ flex: 1, minWidth: 220 }}>
              <p style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 6 }}>
                Can't scan? Enter this secret manually:
              </p>
              <code
                style={{
                  display: 'block', padding: '8px 10px', borderRadius: 6,
                  background: 'rgba(96,130,182,0.08)', border: '1px solid var(--line)',
                  fontFamily: "'JetBrains Mono', monospace", fontSize: 12,
                  color: 'var(--text-2)', wordBreak: 'break-all', marginBottom: 18,
                }}
              >
                {setup.secret}
              </code>

              <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', marginBottom: 8 }}>
                2 · Enter the code from the app
              </p>
              <form onSubmit={confirmEnable} className="flex gap-2">
                <div style={{ position: 'relative', flex: 1 }}>
                  <KeyRound size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
                  <input
                    className="input"
                    style={{ paddingLeft: 36, fontFamily: "'JetBrains Mono', monospace", letterSpacing: '0.15em' }}
                    type="text"
                    inputMode="numeric"
                    placeholder="123456"
                    value={enableCode}
                    onChange={(e) => setEnableCode(e.target.value)}
                    required
                    autoFocus
                  />
                </div>
                <button type="submit" className="btn-primary" disabled={busy || !enableCode.trim()} style={{ fontSize: 13 }}>
                  {busy ? <Loader2 size={14} className="animate-spin" /> : 'Confirm'}
                </button>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* ── Backup codes (shown once after enabling) ───────────────── */}
      {backupCodes && (
        <div
          className="card"
          style={{ padding: '20px', marginBottom: 16, border: '1px solid rgba(245,158,11,0.35)' }}
        >
          <div className="flex items-center gap-2" style={{ marginBottom: 6 }}>
            <AlertTriangle size={15} color="#f59e0b" />
            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>
              Save your backup codes
            </p>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 14 }}>
            Each code works once if you lose access to your authenticator. They will not be shown again.
          </p>
          <div
            style={{
              display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 8,
              padding: '14px 16px', borderRadius: 8,
              background: 'rgba(96,130,182,0.06)', border: '1px solid var(--line)',
              fontFamily: "'JetBrains Mono', monospace", fontSize: 12.5, color: 'var(--text-2)',
              marginBottom: 14,
            }}
          >
            {backupCodes.map((c) => <span key={c}>{c}</span>)}
          </div>
          <button className="btn-secondary" onClick={copyBackupCodes} style={{ fontSize: 13 }}>
            {copied ? <Check size={14} color="#22c55e" /> : <Copy size={14} />}
            Copy all codes
          </button>
        </div>
      )}

      {/* ── Disable ────────────────────────────────────────────────── */}
      {mfaEnabled && (
        <div className="card" style={{ padding: '20px' }}>
          <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', marginBottom: 4 }}>
            Disable two-factor authentication
          </p>
          <p style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 14 }}>
            Requires your password and a current authenticator or backup code.
          </p>
          <form onSubmit={handleDisable} style={{ display: 'flex', flexDirection: 'column', gap: 10, maxWidth: 360 }}>
            <div style={{ position: 'relative' }}>
              <Lock size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
              <input
                className="input"
                style={{ paddingLeft: 36 }}
                type="password"
                placeholder="Password"
                value={disablePassword}
                onChange={(e) => setDisablePassword(e.target.value)}
                required
              />
            </div>
            <div style={{ position: 'relative' }}>
              <KeyRound size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-3)' }} />
              <input
                className="input"
                style={{ paddingLeft: 36, fontFamily: "'JetBrains Mono', monospace" }}
                type="text"
                inputMode="numeric"
                placeholder="Authenticator or backup code"
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value)}
                required
              />
            </div>
            <button
              type="submit"
              disabled={busy || !disablePassword || !disableCode.trim()}
              className="btn-secondary"
              style={{ fontSize: 13, color: '#f87171', justifyContent: 'center' }}
            >
              {busy ? <Loader2 size={14} className="animate-spin" /> : <ShieldOff size={14} />}
              Disable MFA
            </button>
          </form>
        </div>
      )}
    </div>
  )
}
