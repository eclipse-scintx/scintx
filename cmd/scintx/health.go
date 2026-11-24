// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// readyzURL turns the listen address (the SCINTX_ADDR value) into the URL of
// the local /readyz endpoint. It was split out of runHealth so a test can
// call it without a running server.
func readyzURL(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = ":8080"
	}
	// Replace wildcard bind addresses ("", "0.0.0.0", "::") with 127.0.0.1
	// so the probe can dial the local server on Windows and strict stacks.
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
	} else if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	return "http://" + addr + "/readyz"
}

// runHealth probes the gateway's /readyz endpoint.
// It allows a minimal distroless container image without curl or a shell
// to execute container liveness and readiness healthchecks directly.
func runHealth(args []string) error {
	target := ""
	if len(args) > 0 {
		target = strings.TrimSpace(args[0])
	}
	if target == "" {
		target = readyzURL(os.Getenv("SCINTX_ADDR"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned HTTP %d", target, resp.StatusCode)
	}
	return nil
}
