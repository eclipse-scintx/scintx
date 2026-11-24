// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yeeth-security/scintx/internal/config"
	"github.com/yeeth-security/scintx/internal/gateway"
	"github.com/yeeth-security/scintx/internal/server"
)

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

	store := gateway.NewStore()
	orch := gateway.NewOrchestrator(cfg, store)
	srv := server.New(cfg, store, orch)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("scintx gateway %s (%s) listening on %s",
			cfg.Gateway.InstanceID, cfg.Gateway.Version, cfg.Gateway.ListenAddr)
		if serveErr := srv.Start(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
		close(errCh)
	}()

	select {
	case serveErr := <-errCh:
		return serveErr
	case <-ctx.Done():
		log.Printf("shutting down scintx gateway...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}
