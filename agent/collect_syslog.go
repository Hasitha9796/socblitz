package main

import (
	"bufio"
	"context"
	"log"
	"net"
)

// The agent can act as a syslog sink for network devices (switches, firewalls,
// routers) and relay each message to the engine, tagged with the sender's IP.
// This is the "configure the agent to forward network-device logs" path.

func syslogUDP(ctx context.Context, addr string, fwd *Forwarder) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Printf("syslog udp listen %s: %v", addr, err)
		return
	}
	defer pc.Close()
	log.Printf("relaying syslog UDP on %s", addr)
	go func() { <-ctx.Done(); pc.Close() }()
	buf := make([]byte, 64*1024)
	for {
		n, remote, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		host, _, _ := net.SplitHostPort(remote.String())
		fwd.Submit("syslog", string(buf[:n]), host)
	}
}

func syslogTCP(ctx context.Context, addr string, fwd *Forwarder) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("syslog tcp listen %s: %v", addr, err)
		return
	}
	defer ln.Close()
	log.Printf("relaying syslog TCP on %s", addr)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				fwd.Submit("syslog", sc.Text(), host)
			}
		}(conn)
	}
}
