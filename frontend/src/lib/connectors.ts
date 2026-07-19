// Shared connector display metadata. Used by both the Connectors page and the
// dashboard overview so integrations are shown under one consistent set of
// branded names — never the raw upstream product names.

export type ConnectorMeta = { label: string; desc: string; docs: string; category: string }

export const CONNECTOR_META: Record<string, ConnectorMeta> = {
  wazuh_manager:   { label: 'SocBlitz Engine',       desc: 'Detection engine — agent management, rules, FIM', docs: 'https://documentation.wazuh.com', category: 'SIEM' },
  wazuh_indexer:   { label: 'SocBlitz Store',        desc: 'ClickHouse — alert and vulnerability data', docs: 'https://clickhouse.com/docs', category: 'SIEM' },
  velociraptor:    { label: 'SocBlitz Forensics',    desc: 'Endpoint forensics and artifact collection', docs: 'https://docs.velociraptor.app', category: 'DFIR' },
  misp:            { label: 'SocBlitz Threat Intel', desc: 'Threat intelligence — IOCs and events', docs: 'https://www.misp-project.org', category: 'Intel' },
  shuffle:         { label: 'Shuffle SOAR',          desc: 'Security orchestration and automation', docs: 'https://shuffler.io/docs', category: 'SOAR' },
  thehive:         { label: 'TheHive',               desc: 'Case management and investigation', docs: 'https://docs.strangebee.com', category: 'IR' },
  virustotal:      { label: 'VirusTotal',            desc: 'Multi-engine IOC reputation service', docs: 'https://developers.virustotal.com', category: 'Intel' },
  crowdstrike:     { label: 'CrowdStrike',           desc: 'EDR — endpoint detection and isolation', docs: 'https://falcon.crowdstrike.com', category: 'EDR' },
  sentinelone:     { label: 'SentinelOne',           desc: 'EDR — autonomous endpoint protection', docs: 'https://docs.sentinelone.com', category: 'EDR' },
  dfir_iris:       { label: 'DFIR IRIS',             desc: 'Incident response and digital forensics', docs: 'https://docs.dfir-iris.org', category: 'IR' },
}

export const CATEGORY_COLOR: Record<string, string> = {
  SIEM:  'rgba(37,99,235,0.18)',
  DFIR:  'rgba(168,85,247,0.15)',
  Intel: 'rgba(244,63,94,0.12)',
  SOAR:  'rgba(34,197,94,0.10)',
  IR:    'rgba(249,115,22,0.12)',
  EDR:   'rgba(96,130,182,0.12)',
}

export const CATEGORY_TEXT: Record<string, string> = {
  SIEM:  '#60a5fa', DFIR: '#c084fc',
  Intel: '#f87171', SOAR: '#4ade80', IR: '#fb923c', EDR: '#94a3b8',
}

// Resolve a connector_type to its display metadata, with a safe fallback for
// unknown types (title-cased, no upstream name leaked).
export function connectorMeta(type: string): ConnectorMeta {
  return (
    CONNECTOR_META[type] || {
      label: (type || '').replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase()),
      desc: 'Security integration',
      docs: '#',
      category: 'Other',
    }
  )
}
