// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package scintx

import (
	"log/slog"
	"math"
	"sync/atomic"

	"github.com/yeeth-security/scintx/api"
)

// EventDeliverer pushes CloudEvents to external subscribers (webhooks).
// Implementations must be safe for concurrent use and must not panic.
type EventDeliverer interface {
	Deliver(evt api.CloudEvent)
}

// EventEmitter appends CloudEvents to the store with monotonic sequence numbers.
// When a Deliverer is set, each event is also pushed asynchronously.
type EventEmitter struct {
	Source    string
	Store     Store
	Deliverer EventDeliverer
	seq       uint64
}

// NewEventEmitter builds an emitter that records events into store.
func NewEventEmitter(source string, store Store) *EventEmitter {
	return &EventEmitter{Source: source, Store: store}
}

// Emit records a CloudEvent with the next sequence number.
func (e *EventEmitter) Emit(eventType, subject string, data map[string]any) {
	s := atomic.AddUint64(&e.seq, 1)
	if s > math.MaxInt32 { // CloudEvents sequence is int; wrap like TCP ISN after 2^31
		atomic.StoreUint64(&e.seq, 0)
		s = atomic.AddUint64(&e.seq, 1)
	}
	seq := int(s) //nolint:gosec // G115: bounded to MaxInt32 above, cannot overflow
	evt := api.CloudEvent{
		SpecVersion:     "1.0",
		ID:              "evt_" + api.RandHex(),
		Source:          e.Source,
		Type:            eventType,
		Subject:         subject,
		Time:            apiNow(),
		DataContentType: "application/json",
		Data:            data,
		Sequence:        &seq,
	}
	if err := e.Store.AppendEvent(evt); err != nil {
		slog.Error("append event", "type", eventType, "err", err)
	}
	if e.Deliverer != nil {
		e.Deliverer.Deliver(evt)
	}
}
