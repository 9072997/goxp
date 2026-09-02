// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os_test

import (
	"os"
	"testing"
)

func init() {
	pipeDeadlinesTestCases = []pipeDeadlineTest{
		{
			"named overlapped pipe",
			func(t *testing.T) (r, w *os.File) {
				if !canCancelPendingIO() {
					// Every test built on these cases eventually leaves an
					// operation pending on the pipe - most often a write that
					// blocked when the pipe filled, which has no deadline of
					// its own to expire. Freeing one needs CancelIoEx, and
					// CancelIo cannot reach an operation issued by another
					// thread. Individually these tests can pass; under the
					// load of the full package run they hang, which costs the
					// rest of the package rather than just themselves.
					t.Skip("pipe deadlines need CancelIoEx to interrupt a pending operation")
				}
				name := pipeName()
				w = newBytePipe(t, name, true)
				r = newFileOverlapped(t, name, true)
				return
			},
		},
	}
}
