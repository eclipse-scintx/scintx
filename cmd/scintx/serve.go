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
	"strings"
	"syscall"
	"time"

	"github.com/yeeth-security/scintx/api"
	_ "github.com/yeeth-security/scintx/extensions/providers/all"
	"github.com/yeeth-security/scintx/internal/config"
	"github.com/yeeth-security/scintx/internal/gateway"
	"github.com/yeeth-security/scintx/internal/policy"
	"github.com/yeeth-security/scintx/internal/server"
)

// runServe loads configuration, policies, and provider adapters, validates startup
// requirements (#73), and runs the HTTP gateway until interrupted.
func runServe() error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load("")
	if err != nil {
		slog.Error("invalid gateway configuration", "err", err)
		return err
	}

	policies, err := policy.LoadDir(cfg.Gateway.PoliciesDir)
	if err != nil {
		slog.Error("failed to load policies", "dir", cfg.Gateway.PoliciesDir, "err", err)
		return err
	}
	if _, ok := policies[cfg.Gateway.DefaultPolicy]; !ok {
		err := fmt.Errorf("default policy %q not found in %q", cfg.Gateway.DefaultPolicy, cfg.Gateway.PoliciesDir)
		slog.Error("missing default policy", "err", err)
		return err
	}

	adapters, err := api.LoadAdapters()
	if err != nil {
		slog.Error("failed to load provider adapters", "err", err)
		return err
	}

	// Validate required provider adapters at startup (#73).
	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStartup()
	for _, a := range adapters {
		desc := a.Descriptor()
		st := a.CheckAvailability(startupCtx)
		slog.Info("provider adapter registered",
			"slug", desc.Slug,
			"version", desc.AdapterVersion,
			"state", st.State,
			"available", st.Available,
			"reasons", strings.Join(st.Reasons, ","),
		)
		if pcfg, ok := cfg.Providers[desc.Slug]; ok && pcfg.Enabled && pcfg.Required {
			if desc.SupportedSchemaVersion != api.SchemaVersionV1 {
				err := fmt.Errorf("required provider %q has incompatible schema version %q", desc.Slug, desc.SupportedSchemaVersion)
				slog.Error("startup check failed", "err", err)
				return err
			}
			if !st.Available {
				err := fmt.Errorf("required provider %q is unavailable: %v", desc.Slug, st.Reasons)
				slog.Error("startup check failed", "err", err)
				return err
			}
		}
	}

	store := gateway.NewStore()
	orch := gateway.NewOrchestrator(cfg, store, policies, adapters)
	srv := server.New(cfg, store, orch)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.Info("SCINTX gateway listening",
			"addr", cfg.Gateway.Addr,
			"instanceId", cfg.Gateway.InstanceID,
			"defaultPolicy", cfg.Gateway.DefaultPolicy,
			"configRevision", cfg.Revision,
		)
		errCh <- srv.Start(cfg.Gateway.Addr)
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server stopped with error", "err", err)
			return err
		}
		return nil
	}
}
