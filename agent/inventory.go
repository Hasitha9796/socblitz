package main

import (
	"bufio"
	"context"
	"log"
	"os/exec"
	"strings"
	"time"
)

// Package inventory: enumerate installed packages using whichever package
// manager is present, and send them to the engine for vulnerability matching.
// Supports dpkg (Debian/Ubuntu), rpm (RHEL/SUSE), apk (Alpine); extend per-OS.

func runInventory(ctx context.Context, cfg Config, fwd *Forwarder, agentID string) {
	if cfg.InvInterval <= 0 {
		return
	}
	log.Printf("package inventory every %s", cfg.InvInterval)
	for {
		pkgs := collectPackages()
		if len(pkgs) > 0 {
			payload := InventoryPayload{AgentID: agentID, AgentName: cfg.Name, Packages: pkgs}
			if err := fwd.PostInventory(ctx, payload); err != nil {
				log.Printf("inventory post failed: %v", err)
			} else {
				log.Printf("reported %d packages", len(pkgs))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.InvInterval):
		}
	}
}

func collectPackages() []InvPackage {
	switch {
	case have("dpkg-query"):
		return parsePkgs("dpkg-query", []string{"-W", "-f", "${Package} ${Version}\n"})
	case have("rpm"):
		return parsePkgs("rpm", []string{"-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"})
	case have("apk"):
		return parseApk()
	default:
		return nil
	}
}

func have(bin string) bool { _, err := exec.LookPath(bin); return err == nil }

func parsePkgs(bin string, args []string) []InvPackage {
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		return nil
	}
	var pkgs []InvPackage
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 {
			pkgs = append(pkgs, InvPackage{Name: f[0], Version: f[1]})
		}
	}
	return pkgs
}

// apk info -v prints "name-version"; split on the last hyphen-before-digit.
func parseApk() []InvPackage {
	out, err := exec.Command("apk", "info", "-v").Output()
	if err != nil {
		return nil
	}
	var pkgs []InvPackage
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.LastIndex(line, "-"); i > 0 {
			if j := strings.LastIndex(line[:i], "-"); j > 0 {
				pkgs = append(pkgs, InvPackage{Name: line[:j], Version: line[j+1:]})
				continue
			}
		}
		if line != "" {
			pkgs = append(pkgs, InvPackage{Name: line, Version: ""})
		}
	}
	return pkgs
}
