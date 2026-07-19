package main

import (
	"context"
	"testing"
	"time"
)

// decodeNorm is the test helper: raw line -> decoded Event -> UDM via the
// built-in parsers.
func decodeNorm(t *testing.T, msg, program string) UDM {
	t.Helper()
	ev := decode(RawEvent{Message: msg, Timestamp: time.Now().UTC()})
	if program != "" {
		ev.Program = program
	}
	udm, _ := builtinParsers().Normalize(&ev)
	return udm
}

func TestUDMSetGet(t *testing.T) {
	u := UDM{}
	u.Set("principal.user.userid", "root")
	u.Set("principal.ip", "1.2.3.4")
	u.Set("empty", "") // ignored
	if got := u.GetString("principal.user.userid"); got != "root" {
		t.Fatalf("userid = %q", got)
	}
	if got := u.GetString("principal.ip"); got != "1.2.3.4" {
		t.Fatalf("ip = %q", got)
	}
	if u.Has("empty") {
		t.Fatal("empty value should not be set")
	}
	if u.Has("does.not.exist") {
		t.Fatal("missing path should not be present")
	}
}

func TestGrokCompileAndMatch(t *testing.T) {
	re, err := compileGrok(`%{WORD:action} password for %{USERNAME:user} from %{IP:ip}`)
	if err != nil {
		t.Fatal(err)
	}
	got := grokMatch(re, "Failed password for admin from 203.0.113.5")
	if got["action"] != "Failed" || got["user"] != "admin" || got["ip"] != "203.0.113.5" {
		t.Fatalf("grok fields = %#v", got)
	}
}

func TestParserNormalizeSSHFailure(t *testing.T) {
	u := decodeNorm(t,
		"Oct 12 18:00:01 web-01 sshd[999]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2", "")
	checks := map[string]string{
		"metadata.event_type":     "USER_LOGIN",
		"metadata.vendor_name":    "OpenSSH",
		"principal.ip":            "203.0.113.5",
		"principal.port":          "22",
		"target.user.userid":      "admin",
		"security_result.action":  "BLOCK",
		"network.application_protocol": "SSH",
	}
	for path, want := range checks {
		if got := u.GetString(path); got != want {
			t.Errorf("%s = %q, want %q", path, got, want)
		}
	}
}

func TestParserNormalizeSSHRootSuccess(t *testing.T) {
	u := decodeNorm(t,
		"Oct 12 18:00:01 web-01 sshd[999]: Accepted password for root from 10.0.0.9 port 22 ssh2", "")
	if got := u.GetString("security_result.action"); got != "ALLOW" {
		t.Errorf("action = %q, want ALLOW", got)
	}
	if got := u.GetString("security_result.severity"); got != "HIGH" {
		t.Errorf("severity = %q, want HIGH (root login)", got)
	}
	if got := u.GetString("target.user.userid"); got != "root" {
		t.Errorf("user = %q, want root", got)
	}
}

func TestParserNormalizeIptables(t *testing.T) {
	u := decodeNorm(t,
		"Oct 12 18:00:01 fw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.7 DST=10.0.0.1 PROTO=TCP SPT=51000 DPT=22", "")
	if got := u.GetString("metadata.event_type"); got != "NETWORK_CONNECTION" {
		t.Errorf("event_type = %q", got)
	}
	if got := u.GetString("principal.ip"); got != "198.51.100.7" {
		t.Errorf("src ip = %q", got)
	}
	if got := u.GetString("target.port"); got != "22" {
		t.Errorf("dst port = %q", got)
	}
}

func TestYaraLSingleEventRootLogin(t *testing.T) {
	rule, err := ParseYaraL(`
rule root_login {
  meta:
    severity = "MEDIUM"
    technique = "T1078"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "ALLOW"
    $e.target.user.userid = "root"
  condition:
    $e
}`)
	if err != nil {
		t.Fatal(err)
	}
	if rule.IsWindowed() {
		t.Fatal("rule should be single-event")
	}
	set := &YaraLSet{}
	set.add(rule)

	// Matching line fires.
	ev := decode(RawEvent{Message: "Oct 12 18:00:01 web-01 sshd[1]: Accepted password for root from 10.0.0.9 port 22 ssh2", Timestamp: time.Now().UTC()})
	udm, _ := builtinParsers().Normalize(&ev)
	if got := set.EvalSingle(udm, &ev); len(got) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(got))
	} else if got[0].RuleLevel != 8 || len(got[0].Techniques) == 0 {
		t.Fatalf("alert meta wrong: level=%d techniques=%v", got[0].RuleLevel, got[0].Techniques)
	}

	// Non-root success does not fire.
	ev2 := decode(RawEvent{Message: "Oct 12 18:00:01 web-01 sshd[1]: Accepted password for alice from 10.0.0.9 port 22 ssh2", Timestamp: time.Now().UTC()})
	udm2, _ := builtinParsers().Normalize(&ev2)
	if got := set.EvalSingle(udm2, &ev2); len(got) != 0 {
		t.Fatalf("expected 0 alerts for non-root, got %d", len(got))
	}
}

func TestYaraLWindowedBruteForce(t *testing.T) {
	rule, err := ParseYaraL(`
rule brute {
  meta:
    severity = "HIGH"
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $ip
  match:
    $ip over 5m
  condition:
    #e >= 5
}`)
	if err != nil {
		t.Fatal(err)
	}
	if !rule.IsWindowed() {
		t.Fatal("rule should be windowed")
	}
	if _, min := rule.countThreshold(); min != 5 {
		t.Fatalf("threshold = %d, want 5", min)
	}

	set := &YaraLSet{}
	set.add(rule)
	cor := NewCorrelator(set)

	base := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	fires := 0
	// 5 failed logins from the same IP within the window → fires once.
	for i := 0; i < 5; i++ {
		ev := decode(RawEvent{
			Message:   "Jul 14 12:00:00 web-01 sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2",
			Timestamp: base.Add(time.Duration(i) * time.Second),
		})
		udm, _ := builtinParsers().Normalize(&ev)
		fires += len(cor.Observe(udm, &ev))
	}
	if fires != 1 {
		t.Fatalf("expected exactly 1 brute-force alert, got %d", fires)
	}

	// A different source IP shouldn't contribute to the first key's count.
	ev := decode(RawEvent{
		Message:   "Jul 14 12:00:00 web-01 sshd[1]: Failed password for invalid user admin from 8.8.8.8 port 22 ssh2",
		Timestamp: base.Add(6 * time.Second),
	})
	udm, _ := builtinParsers().Normalize(&ev)
	if got := len(cor.Observe(udm, &ev)); got != 0 {
		t.Fatalf("single failure from new IP should not fire, got %d", got)
	}
}

func TestYaraLWindowExpiry(t *testing.T) {
	rule, _ := ParseYaraL(`
rule brute {
  events:
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $ip
  match:
    $ip over 1m
  condition:
    #e >= 3
}`)
	set := &YaraLSet{}
	set.add(rule)
	cor := NewCorrelator(set)

	base := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	// 3 failures but spread 40s apart → the window (1m) only ever holds 2, so
	// the count never reaches 3.
	fires := 0
	for i := 0; i < 3; i++ {
		ev := decode(RawEvent{
			Message:   "Jul 14 12:00:00 web-01 sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2",
			Timestamp: base.Add(time.Duration(i) * 40 * time.Second),
		})
		udm, _ := builtinParsers().Normalize(&ev)
		fires += len(cor.Observe(udm, &ev))
	}
	if fires != 0 {
		t.Fatalf("spread-out failures should not fire (window expiry), got %d", fires)
	}
}

func TestParserStoreOverrideAndList(t *testing.T) {
	s := NewParserStore(builtinParsers(), nil)

	// A custom parser named "sshd" overrides the built-in one.
	list, err := ParseParserYAML([]byte(`name: sshd
log_type: SSH-CUSTOM
check:
  program: sshd
filter:
  - set:
      metadata.event_type: 'CUSTOM_LOGIN'`))
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.custom["sshd"] = list[0]
	s.rebuild()
	s.mu.Unlock()

	// List reports the override as custom, with the new log_type.
	info, ok := s.Get("sshd")
	if !ok || info.Source != "custom" || info.LogType != "SSH-CUSTOM" {
		t.Fatalf("sshd info = %#v", info)
	}
	// The built-in iptables parser is still present and marked builtin.
	if ip, ok := s.Get("iptables"); !ok || ip.Source != "builtin" {
		t.Fatalf("iptables info = %#v", ip)
	}

	// Normalizing an sshd line now uses the override.
	ev := decode(RawEvent{Message: "Oct 12 18:00:01 web-01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", Timestamp: time.Now().UTC()})
	udm, _ := s.Current().Normalize(&ev)
	if got := udm.GetString("metadata.event_type"); got != "CUSTOM_LOGIN" {
		t.Fatalf("event_type = %q, want CUSTOM_LOGIN (override should win)", got)
	}

	// Built-in parsers can't be deleted (no ClickHouse call is made).
	if err := s.Delete(context.Background(), "iptables"); err == nil {
		t.Fatal("deleting a built-in parser should error")
	}
}

func TestBuiltinYaraLLoads(t *testing.T) {
	set := builtinYaraL()
	if set.Count() < 4 {
		t.Fatalf("expected >=4 builtin YARA-L rules, got %d", set.Count())
	}
	// The brute-force rule must be windowed.
	found := false
	for _, r := range set.windowed {
		if r.Name == "ssh_brute_force" {
			found = true
		}
	}
	if !found {
		t.Fatal("ssh_brute_force should be a windowed rule")
	}
}
