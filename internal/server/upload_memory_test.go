// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"testing"

	"github.com/eclipse-scintx/scintx/api"
)

// This file proves that uploads do not bloat memory, even when many arrive
// at the same time.

// patternReader produces an endless, repeatable stream of bytes without
// allocating. It stands in for a large file, so the test itself never holds
// one in memory.
type patternReader struct{ next byte }

func (p *patternReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = p.next
		p.next++
	}
	return len(b), nil
}

// streamUpload posts a file of the given size as a multipart upload. The
// body is produced through a pipe while the handler reads it, the same way
// a real network upload arrives. It returns the HTTP status and the SHA-256
// that the gateway reported for the file.
func streamUpload(handler http.Handler, size int64) (int, string) {
	pipeReader, pipeWriter := io.Pipe()
	// If the handler stops reading early, this unblocks the writer below.
	defer pipeReader.Close()
	mw := multipart.NewWriter(pipeWriter)
	go func() {
		fw, err := mw.CreateFormFile("content", "big.bin")
		if err == nil {
			_, err = io.CopyN(fw, &patternReader{}, size)
		}
		if err == nil {
			err = mw.Close()
		}
		_ = pipeWriter.CloseWithError(err)
	}()
	req := httptest.NewRequest(http.MethodPost, "/v1/submissions", pipeReader)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var created api.Submission
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Artifact.ContentMeta == nil {
		return rec.Code, ""
	}
	return rec.Code, created.Artifact.ContentMeta.SHA256
}

// TestConcurrentUploadsDoNotGrowMemory uploads 8 files of 16 MiB at the same
// time (128 MiB in total) and measures every byte the process allocates
// while doing so.
//
// With streaming, each upload needs only a few small buffers, so the total
// stays far below the size of even ONE file. If anyone ever buffers an
// upload in memory again (io.ReadAll, ParseMultipartForm, ...), the total
// jumps past 128 MiB and this test fails.
func TestConcurrentUploadsDoNotGrowMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 128 MiB to disk; skipped in -short mode")
	}
	const (
		uploads   = 8
		fileSize  = 16 << 20 // 16 MiB per upload
		allocated = 8 << 20  // The limit: 8 MiB for all uploads together.
	)
	blobs := newTestBlobs(t)
	handler, orch := newUploadServer(t, blobs, fileSize)

	// The expected hash, computed by streaming the same pattern.
	hasher := sha256.New()
	_, _ = io.CopyN(hasher, &patternReader{}, fileSize)
	wantSum := hex.EncodeToString(hasher.Sum(nil))

	codes := make([]int, uploads)
	sums := make([]string, uploads)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	var wg sync.WaitGroup
	for i := 0; i < uploads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], sums[i] = streamUpload(handler, fileSize)
		}()
	}
	wg.Wait()
	runtime.ReadMemStats(&after)

	for i := range codes {
		if codes[i] != http.StatusAccepted || sums[i] != wantSum {
			t.Fatalf("upload %d: got status %d and sha256 %q, want 202 and %q", i, codes[i], sums[i], wantSum)
		}
	}
	// TotalAlloc only ever grows. It counts every allocated byte, including
	// ones that were freed again, so a short-lived buffer cannot hide.
	if got := after.TotalAlloc - before.TotalAlloc; got > allocated {
		t.Fatalf("uploading %d MiB allocated %d KiB; the limit is %d KiB", uploads*fileSize>>20, got>>10, allocated>>10)
	} else {
		t.Logf("uploading %d MiB allocated %d KiB of memory", uploads*fileSize>>20, got>>10)
	}

	orch.Wait()
	expectNothingOnDisk(t, blobs, "after all uploads completed")
}
