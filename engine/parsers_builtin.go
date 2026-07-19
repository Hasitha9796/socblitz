package main

// builtinParserYAML is the default Chronicle CBN-style parser set, kept in sync
// with engine/parsers/base.yaml so the engine normalizes to UDM out of the box
// when no parser directory is mounted. One parser per YAML document (--- split).
const builtinParserYAML = `
name: sshd
log_type: SSH
check:
  program: sshd
filter:
  - grok:
      source: message
      patterns:
        - '%{WORD:auth_result} password for (?:invalid user )?%{USERNAME:user} from %{IP:src_ip} port %{PORT:src_port}'
        - '%{WORD:auth_result} password for (?:invalid user )?%{USERNAME:user} from %{IP:src_ip}'
  - set:
      metadata.event_type: 'USER_LOGIN'
      metadata.vendor_name: 'OpenSSH'
      metadata.product_name: 'OpenSSH'
      network.application_protocol: 'SSH'
      principal.ip: '%{src_ip}'
      principal.port: '%{src_port}'
      target.user.userid: '%{user}'
      security_result.summary: '%{auth_result} password'
  - on: '%{auth_result} == Failed'
    set:
      security_result.action: 'BLOCK'
      security_result.category: 'AUTH_VIOLATION'
  - on: '%{auth_result} == Accepted'
    set:
      security_result.action: 'ALLOW'
      security_result.category: 'AUTH_SUCCESS'
  - on: '%{user} == root'
    set:
      security_result.severity: 'HIGH'
---
name: sudo
log_type: SUDO
check:
  program: sudo
filter:
  - grok:
      source: message
      patterns:
        - '%{USERNAME:actor}\s+:.*COMMAND=%{GREEDYDATA:cmd}'
  - kv:
      source: message
  - set:
      metadata.event_type: 'PROCESS_LAUNCH'
      metadata.vendor_name: 'sudo'
      principal.user.userid: '%{actor}'
      target.user.userid: '%{USER}'
      target.process.command_line: '%{cmd}'
      security_result.category: 'PRIVILEGE_ESCALATION'
      security_result.action: 'ALLOW'
---
name: iptables
log_type: NETFILTER
check:
  program: kernel
filter:
  - kv:
      source: message
  - set:
      metadata.event_type: 'NETWORK_CONNECTION'
      metadata.vendor_name: 'netfilter'
      network.direction: 'INBOUND'
      network.ip_protocol: '%{PROTO}'
      principal.ip: '%{SRC}'
      principal.port: '%{SPT}'
      target.ip: '%{DST}'
      target.port: '%{DPT}'
      security_result.category: 'NETWORK_SUSPICIOUS'
`
