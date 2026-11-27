// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package e2e

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/eclipse-scintx/scintx/internal/config"
	"github.com/eclipse-scintx/scintx/internal/gateway"
	"github.com/eclipse-scintx/scintx/internal/server"
)

func newKeepAliveClient(ts *httptest.Server) *http.Client {
	c := ts.Client()
	if tr, ok := c.Transport.(*http.Transport); ok {
		tr = tr.Clone()
		tr.MaxIdleConns = 128
		tr.MaxIdleConnsPerHost = 128
		c.Transport = tr
	}
	return c
}

// BenchmarkHTTPSQLiteSequential measures end-to-end HTTP POST /v1/submissions
// and worker completion throughput against on-disk SQLite from a single client.
func BenchmarkHTTPSQLiteSequential(b *testing.B) {
	cfg := config.Default()
	cfg.Gateway.Workers = 8
	dsn := "file:" + filepath.ToSlash(filepath.Join(b.TempDir(), "bench-seq.db"))

	store, err := gateway.OpenStore(dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	orch := gateway.NewOrchestratorWithExecutor(cfg, store, nil, succeedingHook)
	defer orch.Shutdown()
	srv := server.New(cfg, store, orch)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	client := newKeepAliveClient(ts)
	payload := []byte(`{"artifact":{"purl":"pkg:npm/lodash@4.17.20"}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp, err := client.Post(ts.URL+"/v1/submissions", "application/json", bytes.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			b.Fatalf("status=%d, want 202", resp.StatusCode)
		}
	}
	orch.Wait()
}

// BenchmarkHTTPSQLiteParallel measures concurrent multi-client HTTP submission,
// worker execution, and status verification against on-disk SQLite.
func BenchmarkHTTPSQLiteParallel(b *testing.B) {
	cfg := config.Default()
	cfg.Gateway.Workers = 8
	dsn := "file:" + filepath.ToSlash(filepath.Join(b.TempDir(), "bench-par.db"))

	store, err := gateway.OpenStore(dsn)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()

	orch := gateway.NewOrchestratorWithExecutor(cfg, store, nil, succeedingHook)
	defer orch.Shutdown()
	srv := server.New(cfg, store, orch)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	client := newKeepAliveClient(ts)
	payload := []byte(`{"artifact":{"purl":"pkg:npm/lodash@4.17.20"}}`)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Post(ts.URL+"/v1/submissions", "application/json", bytes.NewReader(payload))
			if err != nil {
				b.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusAccepted {
				b.Errorf("status=%d, want 202", resp.StatusCode)
				return
			}
		}
	})
	orch.Wait()
}

// BenchmarkHTTPMemoryParallel measures raw HTTP + worker pool throughput using
// the in-memory store over keep-alive HTTP connections.
func BenchmarkHTTPMemoryParallel(b *testing.B) {
	cfg := config.Default()
	cfg.Gateway.Workers = 8
	store := gateway.NewMemoryStore()
	defer store.Close()

	orch := gateway.NewOrchestratorWithExecutor(cfg, store, nil, succeedingHook)
	defer orch.Shutdown()
	srv := server.New(cfg, store, orch)
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	client := newKeepAliveClient(ts)
	payload := []byte(`{"artifact":{"purl":"pkg:npm/lodash@4.17.20"}}`)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Post(ts.URL+"/v1/submissions", "application/json", bytes.NewReader(payload))
			if err != nil {
				b.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
	orch.Wait()
}
