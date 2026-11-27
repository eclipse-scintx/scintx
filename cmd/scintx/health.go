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

	// The linter (gosec G704, "request forgery") flags the two calls below,
	// because the URL comes from an argument or from SCINTX_ADDR. That is
	// the purpose of this command: the operator names the gateway to probe.
	// Nothing a remote client sends ever reaches this code. So the finding
	// is switched off for these two lines only, and stays on everywhere else.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil) //nolint:gosec // G704: see above.
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req) //nolint:gosec // G704: see above.
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned HTTP %d", target, resp.StatusCode)
	}
	return nil
}
