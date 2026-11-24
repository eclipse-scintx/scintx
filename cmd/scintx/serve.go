// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eclipse-scintx/scintx/internal/blob"
	"github.com/eclipse-scintx/scintx/internal/config"
	"github.com/eclipse-scintx/scintx/internal/gateway"
	"github.com/eclipse-scintx/scintx/internal/server"
)

// warnAboutRiskyDefaults logs a warning for each default that is fine for a
// local demo but unsafe or misleading in production. Both used to be silent.
func warnAboutRiskyDefaults(cfg *config.Config, orch *gateway.Orchestrator) {
	if cfg.Auth.BearerToken == "" {
		slog.Warn("no bearer token is configured: anyone who can reach this address can create and read submissions; " +
			"set SCINTX_AUTH_BEARER_TOKEN or SCINTX_AUTH_BEARER_TOKEN_FILE")
	}
	if !orch.HasExecutor() {
		slog.Warn("no provider adapters are configured: every submission will end as \"failed\" " +
			"(fail closed), because nothing can scan the artifact")
	}
}

func runServe() error {
	cfgPath := os.Getenv("SCINTX_CONFIG")
	if cfgPath == "" {
		if _, err := os.Stat("gateway.yaml"); err == nil {
			cfgPath = "gateway.yaml"
		}
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	store, err := gateway.OpenStore(cfg.Storage.DSN)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	// This Close is for the early returns below (a bad blob directory, or a
	// listener that fails to start). On a normal shutdown srv.Shutdown has
	// already closed the store, and closing it a second time does nothing.
	// The process is exiting and nothing can act on a close error, so the
	// error is dropped on purpose. It was dropped before too, but silently.
	// The linter (errcheck) flagged that, so it is now spelled out.
	defer func() { _ = store.Close() }()

	// Open the blob directory now, before serving. A missing or read-only
	// volume then stops the gateway at startup with a clear message. Without
	// this check it would only show up as a failed upload much later.
	blobs, err := blob.OpenFileStore(cfg.Storage.BlobDir)
	if err != nil {
		return fmt.Errorf("open blob storage %q: %w", cfg.Storage.BlobDir, err)
	}

	orch := gateway.NewOrchestratorWithBlobs(cfg, store, blobs)
	srv := server.New(cfg, store, orch)
	warnAboutRiskyDefaults(cfg, orch)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting Eclipse SCINTX gateway",
			"instanceId", cfg.Gateway.InstanceID,
			"version", cfg.Gateway.Version,
			"listenAddr", cfg.Gateway.ListenAddr,
			// The revision is a short hash of the resolved configuration. It
			// was computed before but never shown. Logging it lets an
			// operator see at a glance whether two instances run the same
			// configuration.
			"configRevision", cfg.Revision,
		)
		if serveErr := srv.Start(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
		close(errCh)
	}()

	select {
	case serveErr := <-errCh:
		return serveErr
	case <-ctx.Done():
		slog.Info("shutting down Eclipse SCINTX gateway", "instanceId", cfg.Gateway.InstanceID)
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}
