// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

package blob

import (
	"errors"
	"fmt"
	"os"
)

// fileUpload is an upload being written to a staging file.
//
// It lives in its own file to keep file_store.go small. FileStore.NewUpload
// creates it.
type fileUpload struct {
	store *FileStore
	file  *os.File
	// done is true once Commit or Discard has run.
	done bool
}

// Write appends to the staging file. A failure (usually a full disk) is
// wrapped in ErrStorage so the HTTP layer answers 5xx and hides the path.
//
// The bytes go straight to the file. Nothing is kept in memory, which is
// what keeps many uploads at once cheap.
func (u *fileUpload) Write(p []byte) (int, error) {
	n, err := u.file.Write(p)
	if err != nil {
		return n, fmt.Errorf("%w: write upload: %w", ErrStorage, err)
	}
	return n, nil
}

// Commit flushes the file to disk and renames it to its final blob name.
// The flush comes first, so a blob that exists is a blob that is complete.
func (u *fileUpload) Commit(id string) error {
	if u.done {
		return fmt.Errorf("%w: upload already finished", ErrStorage)
	}
	finalPath, err := u.store.blobPath(id)
	if err != nil {
		u.Discard()
		return err
	}
	u.done = true
	stagingPath := u.file.Name()
	syncErr := u.file.Sync()
	closeErr := u.file.Close() // Must be closed before a rename on Windows.
	if err := errors.Join(syncErr, closeErr); err != nil {
		_ = os.Remove(stagingPath)
		return fmt.Errorf("%w: flush upload: %w", ErrStorage, err)
	}
	if err := os.Rename(stagingPath, finalPath); err != nil {
		_ = os.Remove(stagingPath)
		return fmt.Errorf("%w: commit upload: %w", ErrStorage, err)
	}
	return nil
}

// Discard closes and deletes the staging file.
func (u *fileUpload) Discard() {
	if u.done {
		return
	}
	u.done = true
	_ = u.file.Close()
	_ = os.Remove(u.file.Name())
}
