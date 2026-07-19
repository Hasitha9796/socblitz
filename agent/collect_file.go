package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"time"
)

// tailFile follows a log file (like `tail -F`): it starts at EOF, streams new
// lines, and reopens the file if it is rotated/truncated. Cross-platform.
func tailFile(ctx context.Context, path string, fwd *Forwarder) {
	source := "file:" + path
	var offset int64
	for {
		f, err := os.Open(path)
		if err != nil {
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}
		// Start at end on first open so we don't replay history every restart.
		if fi, err := f.Stat(); err == nil {
			if offset == 0 || offset > fi.Size() {
				offset = fi.Size()
			}
		}
		_, _ = f.Seek(offset, io.SeekStart)
		reader := bufio.NewReader(f)
		log.Printf("tailing %s", path)

		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				offset += int64(len(line))
				if s := trimNL(line); s != "" {
					fwd.Submit(source, s, "")
				}
			}
			if err == io.EOF {
				// Detect truncation/rotation.
				if fi, statErr := os.Stat(path); statErr == nil && fi.Size() < offset {
					offset = 0
					break // reopen
				}
				if !sleepCtx(ctx, time.Second) {
					f.Close()
					return
				}
				continue
			}
			if err != nil {
				break // reopen
			}
		}
		f.Close()
		if ctx.Err() != nil {
			return
		}
	}
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
