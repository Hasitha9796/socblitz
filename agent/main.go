package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// socblitz-agent: a single cross-platform (Linux/Windows/macOS) collector that
// forwards host logs to the engine and can relay network-device syslog. It also
// runs File Integrity Monitoring and package inventory. One static binary, no
// external dependencies.

func main() {
	cfg := loadConfig()
	log.Printf("socblitz-agent %s starting; engine=%s name=%s", agentVersion, cfg.EngineURL, cfg.Name)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	agentID, err := enroll(ctx, cfg)
	if err != nil {
		log.Fatalf("enroll: %v", err)
	}
	log.Printf("enrolled as agent_id=%s", agentID)

	fwd := NewForwarder(cfg, agentID)
	go fwd.Run(ctx)
	go heartbeat(ctx, cfg, agentID)

	// Log collectors
	for _, path := range cfg.LogFiles {
		if _, err := os.Stat(path); err == nil {
			go tailFile(ctx, path, fwd)
		} else {
			log.Printf("skip %s (not present)", path)
		}
	}
	if cfg.Journald {
		go journald(ctx, fwd)
	}
	if cfg.SyslogUDP != "" {
		go syslogUDP(ctx, cfg.SyslogUDP, fwd)
	}
	if cfg.SyslogTCP != "" {
		go syslogTCP(ctx, cfg.SyslogTCP, fwd)
	}

	// Endpoint modules
	go runFIM(ctx, cfg, fwd, agentID)
	go runInventory(ctx, cfg, fwd, agentID)

	<-ctx.Done()
	log.Printf("shutting down")
}
