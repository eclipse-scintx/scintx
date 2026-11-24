// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package blobtest holds helpers for tests that need a blob store. The
// gateway and server tests share it, so the helpers exist only once.
package blobtest

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/eclipse-scintx/scintx/internal/blob"
)

// Store is a file blob store in a temporary directory. It remembers the
// directory so a test can look at what is really on disk.
type Store struct {
	*blob.FileStore
	// Dir is the root of the blob directory.
	Dir string
}

// Open creates a blob store in a fresh temporary directory. The directory is
// removed when the test ends.
func Open(t testing.TB) *Store {
	t.Helper()
	dir := t.TempDir()
	files, err := blob.OpenFileStore(dir)
	if err != nil {
		t.Fatalf("OpenFileStore failed: %v", err)
	}
	return &Store{FileStore: files, Dir: dir}
}

// Files returns every file under the blob directory: committed blobs and
// staged uploads alike. Paths are relative to the directory.
//
// Tests use it to prove that nothing was left behind. It reads the directory
// itself instead of asking the store. That matters on Windows, where a
// leaked upload that is still open cannot be deleted and so would not show
// up in the count returned by RemoveStaleUploads.
func (s *Store) Files(t testing.TB) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(s.Dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, err := filepath.Rel(s.Dir, path)
		files = append(files, filepath.ToSlash(rel))
		return err
	})
	if err != nil {
		t.Fatalf("reading the blob directory failed: %v", err)
	}
	return files
}
