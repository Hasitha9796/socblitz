package main

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"log"
)

// The ingest layer accepts events two ways:
//   1. HTTP  POST /ingest  — a JSON array of RawEvent (how the socblitz agent forwards)
//   2. syslog UDP :514     — one message per datagram (network devices / rsyslog)
// Both drop RawEvents onto the pipeline channel.

type Server struct {
	pipeline  chan RawEvent
	enrollKey string
	ch        *CHClient
	vuln      *VulnFeed
	rules     *RuleSet
	yaral     *YaraLSet
	parsers   *ParserStore
}

func NewServer(pipeline chan RawEvent, enrollKey string, ch *CHClient, vuln *VulnFeed, rules *RuleSet, yaral *YaraLSet, parsers *ParserStore) *Server {
	return &Server{pipeline: pipeline, enrollKey: enrollKey, ch: ch, vuln: vuln, rules: rules, yaral: yaral, parsers: parsers}
}

// authed enforces the shared enroll key (unless none is configured).
func (s *Server) authed(r *http.Request) bool {
	return s.enrollKey == "" || r.Header.Get("X-Enroll-Key") == s.enrollKey
}

func (s *Server) httpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", s.handleIngest)       // logs
	mux.HandleFunc("/fim", s.handleFIM)             // file-integrity events
	mux.HandleFunc("/inventory", s.handleInventory) // package inventory → vuln
	mux.HandleFunc("/enroll", s.handleEnroll)
	mux.HandleFunc("/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("/agents", s.handleAgents)
	// Workbench (SocBlitz Engine UI: Extractor / Rule Generation / Test)
	mux.HandleFunc("/test", s.handleTestLog)
	mux.HandleFunc("/extractor/test", s.handleExtractorTest)
	mux.HandleFunc("/rules/test", s.handleRuleTest)
	mux.HandleFunc("/rules", s.handleListRules)
	// Chronicle-style workbench: normalize to UDM, test parsers, test YARA-L
	mux.HandleFunc("/normalize", s.handleNormalize)
	mux.HandleFunc("/parser/test", s.handleParserTest)
	mux.HandleFunc("/yaral/test", s.handleYaraLTest)
	mux.HandleFunc("/yaral/rules", s.handleListYaraL)
	// Parser management (list / view / create / edit / delete)
	mux.HandleFunc("/parsers", s.handleParsers)      // GET list, POST upsert
	mux.HandleFunc("/parsers/", s.handleParserByName) // GET/PUT/DELETE /parsers/<name>
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Simple shared-secret auth for the MVP (mTLS/per-agent tokens come later).
	if !s.authed(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var batch []RawEvent
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, ev := range batch {
		s.pipeline <- ev
		if ev.AgentID != "" {
			s.touchFromEvent(ev.AgentID)
		}
	}
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(batch)})
}

// StartHTTP serves the ingest API (blocking).
func (s *Server) StartHTTP(addr string) error {
	srv := &http.Server{Addr: addr, Handler: s.httpHandler(), ReadTimeout: 30 * time.Second}
	log.Printf("ingest: HTTP listening on %s", addr)
	return srv.ListenAndServe()
}

// StartSyslogUDP receives raw syslog datagrams (blocking).
func (s *Server) StartSyslogUDP(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	log.Printf("ingest: syslog UDP listening on %s", addr)
	buf := make([]byte, 64*1024)
	for {
		n, remote, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("syslog read error: %v", err)
			continue
		}
		host, _, _ := net.SplitHostPort(remote.String())
		s.pipeline <- RawEvent{
			Message:   string(buf[:n]),
			Source:    "syslog",
			SrcHost:   host,
			Timestamp: time.Now().UTC(),
		}
	}
}

// StartSyslogTCP receives newline-delimited syslog over TCP (blocking).
func (s *Server) StartSyslogTCP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("ingest: syslog TCP listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 64*1024), 1024*1024)
			for sc.Scan() {
				s.pipeline <- RawEvent{
					Message:   sc.Text(),
					Source:    "syslog-tcp",
					SrcHost:   host,
					Timestamp: time.Now().UTC(),
				}
			}
		}(conn)
	}
}
