// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// SPDX-License-Identifier: EPL-2.0
package scintx

import "time"

// apiNow is the clock used by the reference impl (UTC).
// Separated so tests can swap it later if needed.
func apiNow() time.Time {
	return time.Now().UTC()
}
