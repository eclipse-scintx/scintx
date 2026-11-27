// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package blob

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/eclipse-scintx/scintx/api"
)

// blobSuffix marks a committed blob file. stagingDirName holds uploads that
// are still being written.
const (
	blobSuffix     = ".blob"
	stagingDirName = "staging"
)

// FileStore is a Store backed by one directory on local disk:
//
//	<dir>/staging/upload-*.part    uploads in progress
//	<dir>/<submission-id>.blob     committed blobs
//
// Both live on the same filesystem, so Commit can move a finished upload into
// place with one atomic rename. A reader never sees a half-written blob.
//
// When several gateway instances share one database, they must also share
// this directory. Otherwise a worker on one instance cannot read a blob that
// another instance received.
type FileStore struct {
	dir        string
	stagingDir string
}

// OpenFileStore creates the directories if needed and checks that they are
// writable. Checking now means a bad volume mount stops the gateway at
// startup, instead of failing the first upload hours later.
func OpenFileStore(dir string) (*FileStore, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, fmt.Errorf("%w: blob directory must not be empty", ErrStorage)
	}
	stagingDir := filepath.Join(dir, stagingDirName)
	if err := os.MkdirAll(stagingDir, 0o750); err != nil {
		return nil, fmt.Errorf("%w: create blob directory: %w", ErrStorage, err)
	}
	probe, err := os.CreateTemp(stagingDir, "probe-*")
	if err != nil {
		return nil, fmt.Errorf("%w: blob directory is not writable: %w", ErrStorage, err)
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	return &FileStore{dir: dir, stagingDir: stagingDir}, nil
}

// blobPath returns the file path for a submission ID.
//
// The ID is checked first. A valid ID is "submission-" plus 32 hex
// characters, so it cannot contain a path separator or "..". That is what
// stops an ID from pointing at a file outside the blob directory.
func (s *FileStore) blobPath(id string) (string, error) {
	if !api.IsValidSubmissionID(id) {
		return "", fmt.Errorf("%w: invalid blob id %q", ErrStorage, id)
	}
	return filepath.Join(s.dir, id+blobSuffix), nil
}

// NewUpload creates an empty file in the staging directory. os.CreateTemp
// picks a unique name and creates it with owner-only permissions (0600).
func (s *FileStore) NewUpload() (Upload, error) {
	file, err := os.CreateTemp(s.stagingDir, "upload-*.part")
	if err != nil {
		return nil, fmt.Errorf("%w: start upload: %w", ErrStorage, err)
	}
	return &fileUpload{store: s, file: file}, nil
}

// Open returns the blob file itself. Reading from it streams from disk.
func (s *FileStore) Open(id string) (io.ReadCloser, error) {
	path, err := s.blobPath(id)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: open blob: %w", ErrStorage, err)
	}
	return file, nil
}

// Delete removes the blob file. A missing file counts as success, so a
// second delete (for example by the sweeper) is harmless.
func (s *FileStore) Delete(id string) error {
	path, err := s.blobPath(id)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: delete blob: %w", ErrStorage, err)
	}
	return nil
}

// List returns the committed blobs. Files that are not "<valid id>.blob" are
// ignored, so a stray file in the directory is never treated as a blob.
func (s *FileStore) List() ([]Entry, error) {
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("%w: list blobs: %w", ErrStorage, err)
	}
	var entries []Entry
	for _, file := range files {
		id, isBlob := strings.CutSuffix(file.Name(), blobSuffix)
		if file.IsDir() || !isBlob || !api.IsValidSubmissionID(id) {
			continue
		}
		info, err := file.Info()
		if err != nil {
			continue // The blob was deleted while we were listing. Skip it.
		}
		entries = append(entries, Entry{ID: id, ModTime: info.ModTime()})
	}
	return entries, nil
}

// RemoveStaleUploads deletes staging files last written more than olderThan
// ago. A file that is still being written has a fresh modification time, so
// an upload in progress is never removed.
func (s *FileStore) RemoveStaleUploads(olderThan time.Duration) (int, error) {
	files, err := os.ReadDir(s.stagingDir)
	if err != nil {
		return 0, fmt.Errorf("%w: list uploads: %w", ErrStorage, err)
	}
	cutoff := time.Now().Add(-olderThan)
	removed := 0
	for _, file := range files {
		info, err := file.Info()
		if err != nil || file.IsDir() || info.ModTime().After(cutoff) {
			continue
		}
		if os.Remove(filepath.Join(s.stagingDir, file.Name())) == nil {
			removed++
		}
	}
	return removed, nil
}
