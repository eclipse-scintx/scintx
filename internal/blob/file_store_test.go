// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package blob

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// stagedFiles returns the names of the files in the staging directory.
func stagedFiles(t *testing.T, store *FileStore) []string {
	t.Helper()
	files, err := os.ReadDir(store.stagingDir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name())
	}
	return names
}

func TestFileStoreUploadCommitOpenDelete(t *testing.T) {
	store, err := OpenFileStore(filepath.Join(t.TempDir(), "nested", "blobs"))
	if err != nil {
		t.Fatalf("OpenFileStore failed: %v", err)
	}
	id := api.NewID("submission")

	upload, err := store.NewUpload()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Write([]byte("hello ")); err != nil {
		t.Fatal(err)
	}
	if _, err := upload.Write([]byte("blob")); err != nil {
		t.Fatal(err)
	}

	// Before Commit the bytes must not be readable under the ID.
	if _, err := store.Open(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound before commit, got %v", err)
	}
	if err := upload.Commit(id); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	// Discard after Commit must not delete the committed blob.
	upload.Discard()
	if left := stagedFiles(t, store); len(left) != 0 {
		t.Fatalf("expected an empty staging directory after commit, got %v", left)
	}

	reader, err := store.Open(id)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	data, _ := io.ReadAll(reader)
	_ = reader.Close()
	if string(data) != "hello blob" {
		t.Fatalf("got %q, want %q", data, "hello blob")
	}

	entries, err := store.List()
	if err != nil || len(entries) != 1 || entries[0].ID != id {
		t.Fatalf("unexpected List result: %+v err=%v", entries, err)
	}

	// Delete removes the blob. A second delete is not an error.
	for i := 0; i < 2; i++ {
		if err := store.Delete(id); err != nil {
			t.Fatalf("Delete #%d failed: %v", i+1, err)
		}
	}
	if _, err := store.Open(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

// TestOpenFileStoreFailsFast checks that a bad directory setting stops the
// gateway at startup, and not at the first upload.
func TestOpenFileStoreFailsFast(t *testing.T) {
	if _, err := OpenFileStore("  "); !errors.Is(err, ErrStorage) {
		t.Fatalf("expected ErrStorage for an empty directory setting, got %v", err)
	}
	// A regular file is in the way, so the directory cannot be created.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(filepath.Join(blocker, "blobs")); !errors.Is(err, ErrStorage) {
		t.Fatalf("expected ErrStorage for an unusable directory, got %v", err)
	}
}

func TestFileStoreDiscardRemovesTheUpload(t *testing.T) {
	store, err := OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	upload, err := store.NewUpload()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = upload.Write([]byte("never used"))
	upload.Discard()
	upload.Discard() // A second call must be harmless.
	if left := stagedFiles(t, store); len(left) != 0 {
		t.Fatalf("expected Discard to remove the staging file, got %v", left)
	}
	if err := upload.Commit(api.NewID("submission")); err == nil {
		t.Fatal("expected Commit after Discard to fail")
	}
}

// TestFileStoreRejectsUnsafeIDs checks that an ID can never name a file
// outside the blob directory.
func TestFileStoreRejectsUnsafeIDs(t *testing.T) {
	store, err := OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "../escape", `..\escape`, "submission-short", "submission-" + "../../../../etc/passwd0000000000000"} {
		if _, err := store.Open(id); !errors.Is(err, ErrStorage) {
			t.Errorf("Open(%q): expected ErrStorage, got %v", id, err)
		}
		if err := store.Delete(id); !errors.Is(err, ErrStorage) {
			t.Errorf("Delete(%q): expected ErrStorage, got %v", id, err)
		}
		upload, err := store.NewUpload()
		if err != nil {
			t.Fatal(err)
		}
		if err := upload.Commit(id); !errors.Is(err, ErrStorage) {
			t.Errorf("Commit(%q): expected ErrStorage, got %v", id, err)
		}
	}
	// A refused Commit must also clean up its staging file.
	if left := stagedFiles(t, store); len(left) != 0 {
		t.Fatalf("expected no staging files after refused commits, got %v", left)
	}
}

// TestFileStoreRemoveStaleUploads checks that only old, abandoned uploads
// are removed. An upload that is still being written must survive.
func TestFileStoreRemoveStaleUploads(t *testing.T) {
	store, err := OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	abandoned, _ := store.NewUpload()
	active, _ := store.NewUpload()
	_, _ = abandoned.Write([]byte("left behind by a crash"))
	_, _ = active.Write([]byte("still uploading"))

	// Simulate a crash: the process is gone, so its file handle is closed,
	// but the file is still on disk. (Windows also refuses to delete a file
	// that is still open, so this keeps the test portable.)
	abandonedFile := abandoned.(*fileUpload).file
	abandonedPath := abandonedFile.Name()
	if err := abandonedFile.Close(); err != nil {
		t.Fatal(err)
	}
	// Make the abandoned upload look one hour old.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(abandonedPath, old, old); err != nil {
		t.Fatal(err)
	}

	removed, err := store.RemoveStaleUploads(15 * time.Minute)
	if err != nil || removed != 1 {
		t.Fatalf("expected 1 stale upload removed, got %d err=%v", removed, err)
	}
	if left := stagedFiles(t, store); len(left) != 1 {
		t.Fatalf("expected the active upload to survive, got %v", left)
	}
	if err := active.Commit(api.NewID("submission")); err != nil {
		t.Fatalf("the active upload must still be committable: %v", err)
	}
}
