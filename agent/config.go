package main

import (
	"os"
	"strings"
	"time"
)

type Config struct {
	EngineURL   string
	EnrollKey   string
	Name        string        // display name (defaults to hostname)
	LogFiles    []string      // files to tail
	Journald    bool          // stream journald on Linux
	SyslogUDP   string        // listen addr for relayed syslog, e.g. ":5514" ("" = off)
	SyslogTCP   string        // "" = off
	FIMPaths    []string      // directories/files to monitor for integrity
	FIMInterval time.Duration
	InvInterval time.Duration // package inventory interval (0 = off)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func csv(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func dur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func loadConfig() Config {
	host, _ := os.Hostname()
	return Config{
		EngineURL:   env("ENGINE_URL", "http://engine:8090"),
		EnrollKey:   env("AGENT_ENROLL_KEY", ""),
		Name:        env("AGENT_NAME", host),
		LogFiles:    csv(env("AGENT_LOG_FILES", "/var/log/auth.log,/var/log/syslog")),
		Journald:    env("AGENT_JOURNALD", "true") == "true",
		SyslogUDP:   env("AGENT_SYSLOG_UDP", ""),
		SyslogTCP:   env("AGENT_SYSLOG_TCP", ""),
		FIMPaths:    csv(env("AGENT_FIM_PATHS", "")),
		FIMInterval: dur("AGENT_FIM_INTERVAL", 60*time.Second),
		InvInterval: dur("AGENT_INV_INTERVAL", 0),
	}
}
