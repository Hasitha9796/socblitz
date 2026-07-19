package main

import (
	"bufio"
	"context"
	"log"
	"os/exec"
	"runtime"
)

// On Linux, stream the systemd journal via `journalctl -f` if available. Done by
// exec (not cgo/libsystemd) so the single binary stays static and dependency-free.
func journald(ctx context.Context, fwd *Forwarder) {
	if runtime.GOOS != "linux" {
		return
	}
	if _, err := exec.LookPath("journalctl"); err != nil {
		return
	}
	cmd := exec.CommandContext(ctx, "journalctl", "-f", "-n0", "-o", "short-iso")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	log.Printf("streaming journald")
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fwd.Submit("journald", sc.Text(), "")
	}
	_ = cmd.Wait()
}
