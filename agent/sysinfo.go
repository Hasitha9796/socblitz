package main

import (
	"net"
	"os"
	"regexp"
	"runtime"
)

// localIP returns the primary outbound IP (best-effort, no traffic sent).
func localIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String()
	}
	return ""
}

var prettyRE = regexp.MustCompile(`(?m)^PRETTY_NAME="?([^"\n]+)"?`)

// osVersion returns a human-readable OS description.
func osVersion() string {
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/etc/os-release"); err == nil {
			if m := prettyRE.FindSubmatch(b); m != nil {
				return string(m[1])
			}
		}
	}
	return runtime.GOOS + "/" + runtime.GOARCH
}
