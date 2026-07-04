import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Workflow, Play, Clock, CheckCircle, XCircle,
  RefreshCw, Plus, ChevronRight, Zap
} from 'lucide-react'
import toast from 'react-hot-toast'
import { formatDistanceToNow } from 'date-fns'
import { api } from '../stores/auth'

const EXAMPLE_WORKFLOWS = [
  {
    id: 'auto-triage',
    name: 'Auto-triage critical alerts',
    description: 'Automatically enrich and escalate critical severity alerts from Wazuh',
    trigger: 'Alert: severity=critical',
    steps: ['Enrich IP via VirusTotal', 'Query MISP for matching IOCs', 'Create TheHive case', 'Notify Slack #soc-critical'],
    enabled: true,
    runs: 47,
    last_run: new Date(Date.now() - 3600000).toISOString(),
  },
  {
    id: 'block-ip',
    name: 'Block malicious IP',
    description: 'Trigger Wazuh active response to block an IP confirmed as malicious',
    trigger: 'Manual / Threat Intel: verdict=malicious',
    steps: ['Check VirusTotal score', 'Wazuh: firewall-drop active response', 'Log to case', 'Update MISP event'],
    enabled: true,
    runs: 12,
    last_run: new Date(Date.now() - 86400000).toISOString(),
  },
  {
    id: 'collect-forensics',
    name: 'Velociraptor forensic collection',
    description: 'Collect memory and disk artifacts from a flagged endpoint via Velociraptor',
    trigger: 'Case: priority=critical',
    steps: ['Identify agent by IP', 'Run Windows.Memory.Acquisition', 'Run Windows.System.Pslist', 'Upload artifacts to case'],
    enabled: false,
    runs: 3,
    last_run: new Date(Date.now() - 604800000).toISOString(),
  },
  {
    id: 'threat-intel-feed',
    name: 'Ingest threat feed to MISP',
    description: 'Pull latest IOCs from configured feeds and import to MISP',
    trigger: 'Schedule: every 6h',
    steps: ['Fetch OSINT feeds', 'Deduplicate IOCs', 'Push to MISP', 'Tag new events'],
    enabled: true,
    runs: 182,
    last_run: new Date(Date.now() - 7200000).toISOString(),
  },
]

export function SOAR() { return <SettingsSOAR /> }
export function Settings() { return <SettingsSOAR /> }

function SettingsSOAR() {
  const [expanded, setExpanded] = useState<string | null>(null)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ── */}
      <div className="page-header">
        <div>
          <h1 className="page-title">SOAR</h1>
          <p className="page-sub">Security orchestration, automation, and response workflows</p>
        </div>
        <button className="btn-primary">
          <Plus size={13} /> New workflow
        </button>
      </div>

      {/* ── Stats row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
        {[
          { label: 'Total workflows',   value: EXAMPLE_WORKFLOWS.length,                                           color: '#60a5fa' },
          { label: 'Enabled',           value: EXAMPLE_WORKFLOWS.filter((w) => w.enabled).length,                  color: '#22c55e' },
          { label: 'Total executions',  value: EXAMPLE_WORKFLOWS.reduce((acc, w) => acc + w.runs, 0),              color: '#fbbf24' },
        ].map(({ label, value, color }) => (
          <div key={label} className="metric-card">
            <p className="metric-label">{label}</p>
            <p className="metric-value" style={{ color }}>{value}</p>
          </div>
        ))}
      </div>

      {/* ── Workflow list ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {EXAMPLE_WORKFLOWS.map((wf) => {
          const isExp = expanded === wf.id
          return (
            <div
              key={wf.id}
              className="card"
              style={{
                padding: 0, overflow: 'hidden',
                border: `1px solid ${wf.enabled ? 'rgba(37,99,235,0.2)' : 'var(--line)'}`,
              }}
            >
              {/* Header row */}
              <button
                style={{
                  display: 'flex', alignItems: 'center', gap: 12, padding: '14px 16px',
                  width: '100%', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left',
                }}
                onClick={() => setExpanded(isExp ? null : wf.id)}
              >
                {/* Enabled dot */}
                <div
                  style={{
                    width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                    background: wf.enabled ? '#22c55e' : '#334155',
                    boxShadow: wf.enabled ? '0 0 6px rgba(34,197,94,0.5)' : 'none',
                  }}
                />

                {/* Icon */}
                <div
                  style={{
                    width: 34, height: 34, borderRadius: 7, flexShrink: 0,
                    background: wf.enabled ? 'rgba(37,99,235,0.12)' : 'rgba(96,130,182,0.08)',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}
                >
                  <Workflow size={16} color={wf.enabled ? '#60a5fa' : '#475569'} />
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)', marginBottom: 2 }}>
                    {wf.name}
                  </p>
                  <p style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {wf.description}
                  </p>
                </div>

                {/* Trigger pill */}
                <span
                  style={{
                    fontSize: 10, padding: '2px 8px', borderRadius: 3, flexShrink: 0,
                    background: 'rgba(96,130,182,0.08)',
                    border: '1px solid rgba(96,130,182,0.12)',
                    color: 'var(--text-3)', fontFamily: 'JetBrains Mono,monospace',
                    display: 'none',
                  }}
                  className="hidden sm:inline"
                >
                  {wf.trigger}
                </span>

                {/* Runs count */}
                <span style={{ fontSize: 11, color: 'var(--text-3)', fontVariantNumeric: 'tabular-nums', flexShrink: 0 }}>
                  {wf.runs} runs
                </span>

                <ChevronRight
                  size={14}
                  color="var(--text-3)"
                  style={{ transition: 'transform 0.15s', transform: isExp ? 'rotate(90deg)' : 'none', flexShrink: 0 }}
                />
              </button>

              {/* Expanded detail */}
              {isExp && (
                <div
                  style={{
                    borderTop: '1px solid var(--line)',
                    padding: '14px 16px',
                    background: 'rgba(11,16,26,0.5)',
                    display: 'grid', gridTemplateColumns: '1fr auto', gap: 16,
                  }}
                >
                  {/* Steps */}
                  <div>
                    <p style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-3)', marginBottom: 10 }}>
                      Automation steps
                    </p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {wf.steps.map((step, i) => (
                        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span
                            style={{
                              width: 20, height: 20, borderRadius: '50%', flexShrink: 0,
                              background: 'rgba(37,99,235,0.15)', border: '1px solid rgba(37,99,235,0.25)',
                              display: 'flex', alignItems: 'center', justifyContent: 'center',
                              fontSize: 9, fontWeight: 700, color: '#60a5fa', fontVariantNumeric: 'tabular-nums',
                            }}
                          >
                            {i + 1}
                          </span>
                          <span style={{ fontSize: 12, color: 'var(--text-2)' }}>{step}</span>
                          {i < wf.steps.length - 1 && (
                            <div
                              style={{
                                width: 1, height: 12, background: 'rgba(37,99,235,0.25)',
                                position: 'absolute', left: 26, marginTop: 20,
                              }}
                            />
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-end' }}>
                    <div style={{ fontSize: 10, color: 'var(--text-3)', textAlign: 'right', marginBottom: 4 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 3 }}>
                        <Clock size={10} />
                        Last run {formatDistanceToNow(new Date(wf.last_run), { addSuffix: true })}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <Zap size={10} />
                        Trigger: {wf.trigger}
                      </div>
                    </div>

                    <button className="btn-primary" style={{ fontSize: 11, padding: '5px 12px' }}>
                      <Play size={11} /> Run now
                    </button>
                    <button className="btn-secondary" style={{ fontSize: 11, padding: '5px 12px' }}>
                      {wf.enabled ? 'Disable' : 'Enable'}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* ── Shuffle CTA ── */}
      <div
        className="card"
        style={{
          padding: 20,
          background: 'linear-gradient(135deg, rgba(37,99,235,0.07) 0%, rgba(96,130,182,0.03) 100%)',
          border: '1px solid rgba(37,99,235,0.15)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div
            style={{
              width: 42, height: 42, borderRadius: 10, flexShrink: 0,
              background: 'rgba(37,99,235,0.15)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}
          >
            <Workflow size={20} color="#60a5fa" />
          </div>
          <div style={{ flex: 1 }}>
            <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-1)', marginBottom: 3 }}>
              Powered by Shuffle SOAR
            </p>
            <p style={{ fontSize: 12, color: 'var(--text-3)', lineHeight: 1.5 }}>
              Visual workflow builder with 800+ integrations. Connect your tools, automate playbooks, and respond to threats at machine speed.
            </p>
          </div>
          <a
            href="http://localhost:3001"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary"
            style={{ flexShrink: 0 }}
          >
            Open Shuffle
          </a>
        </div>
      </div>
    </div>
  )
}
