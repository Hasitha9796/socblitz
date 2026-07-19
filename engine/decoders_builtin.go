package main

// builtinDecoderYAML is the default decoder set (kept in sync with
// engine/decoders/base.yml) so the engine works with no mounted decoders.
// Wazuh 5.0 decoder asset shape, restructured for SocBlitz (regex parse).
const builtinDecoderYAML = `
name: decoder/sshd/0
metadata:
  module: sshd
  title: OpenSSH authentication events
  description: Extracts user and source IP from SSH login success/failure
  compatibility: OpenSSH 7.x and later
  author:
    name: SocBlitz
    date: 2026/07/12
check:
  program: sshd
parse|message:
  - 'Failed password for (?:invalid user )?(?P<dstuser>\S+) from (?P<srcip>\d{1,3}(?:\.\d{1,3}){3})'
  - 'Accepted password for (?P<dstuser>\S+) from (?P<srcip>\d{1,3}(?:\.\d{1,3}){3})'
normalize:
  - map:
      event.category: authentication
      event.module: sshd
---
name: decoder/sudo/0
metadata:
  module: sudo
  title: sudo command execution
  description: Extracts the invoking user and executed command
  compatibility: sudo 1.8+
  author:
    name: SocBlitz
    date: 2026/07/12
check:
  program: sudo
parse|message:
  - '(?P<dstuser>\S+)\s+:.*COMMAND=(?P<command>.*)$'
normalize:
  - map:
      event.category: privilege_escalation
      event.module: sudo
---
name: decoder/iptables/0
metadata:
  module: iptables
  title: Netfilter/iptables packet log
  description: Extracts source IP and destination port from kernel firewall logs
  compatibility: Linux netfilter
  author:
    name: SocBlitz
    date: 2026/07/12
check:
  program: kernel
parse|message:
  - 'SRC=(?P<srcip>\d{1,3}(?:\.\d{1,3}){3}).*DPT=(?P<dstport>\d+)'
normalize:
  - map:
      event.category: network
      event.module: iptables
`
