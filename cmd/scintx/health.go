// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// runHealth probes the gateway's /readyz endpoint.
// It allows a minimal distroless container image without curl or a shell
// to execute container liveness and readiness healthchecks directly.
func runHealth(args []string) error {
	target := ""
	if len(args) > 0 {
		target = strings.TrimSpace(args[0])
	}
	if target == "" {
		addr := strings.TrimSpace(os.Getenv("SCINTX_ADDR"))
		if addr == "" {
			addr = ":8080"
		}
		if strings.HasPrefix(addr, ":") {
			addr = "127.0.0.1" + addr
		}
		target = "http://" + addr + "/readyz"
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
