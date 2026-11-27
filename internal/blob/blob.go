// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0

// Package blob stores uploaded artifact bytes for as long as a submission
// needs them, and no longer.
//
// Three rules shape the design:
//
//  1. Bytes are always streamed. Nothing here ever holds a whole upload in
//     memory, so many large uploads at once do not grow the heap.
//  2. A blob is named after its submission ID. One blob has exactly one
//     owner, so deleting it needs no reference counting.
//  3. A blob is deleted as soon as its submission is finished. A sweeper in
//     the gateway package removes whatever a crash leaves behind.
package blob

import (
	"errors"
	"io"
	"time"
)

// ErrNotFound is returned by Open when no blob exists for the ID.
var ErrNotFound = errors.New("blob not found")

// ErrStorage wraps every failure of the storage backend itself, such as a
// full disk. Callers use it to tell "our storage broke" (a 5xx) apart from
// "the client sent a bad request" (a 4xx). The wrapped detail can contain
// file paths, so it belongs in the log and not in an API response.
var ErrStorage = errors.New("blob storage error")

// Store keeps uploaded artifact content until its submission finishes.
type Store interface {
	// NewUpload starts a new upload. The bytes written to it are not visible
	// under any ID until Commit is called.
	NewUpload() (Upload, error)
	// Open returns a stream of the blob stored for the submission ID. The
	// caller must close it. It returns ErrNotFound if there is no such blob.
	Open(id string) (io.ReadCloser, error)
	// Delete removes the blob for the submission ID. Deleting a blob that
	// does not exist is not an error.
	Delete(id string) error
	// List returns every committed blob. The sweeper uses it to find blobs
	// that should already be gone.
	List() ([]Entry, error)
	// RemoveStaleUploads deletes uploads that were started but neither
	// committed nor discarded, and were last written more than olderThan
	// ago. A crash in the middle of an upload leaves these behind. It
	// returns how many it removed.
	RemoveStaleUploads(olderThan time.Duration) (int, error)
}

// Upload is one upload in progress. It is used by a single goroutine.
type Upload interface {
	// Write appends bytes to the upload.
	io.Writer
	// Commit makes the upload durable and stores it under the submission ID.
	Commit(id string) error
	// Discard throws the upload away. It is safe to call more than once and
	// does nothing after a successful Commit. This makes "defer Discard()"
	// a simple way to never leak an upload on an error path.
	Discard()
}

// Entry describes one committed blob.
type Entry struct {
	// ID is the submission ID the blob belongs to.
	ID string
	// ModTime is when the blob was written.
	ModTime time.Time
}
