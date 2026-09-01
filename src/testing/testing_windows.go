// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package testing

import (
	"errors"
	"internal/syscall/windows"
	"math/bits"
	"syscall"
	"time"
)

// isWindowsRetryable reports whether err is a Windows error code
// that may be fixed by retrying a failed filesystem operation.
func isWindowsRetryable(err error) bool {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			break
		}
		err = unwrapped
	}
	if err == syscall.ERROR_ACCESS_DENIED {
		return true // Observed in https://go.dev/issue/50051.
	}
	if err == windows.ERROR_SHARING_VIOLATION {
		return true // Observed in https://go.dev/issue/51442.
	}
	return false
}

// highPrecisionTime represents a single point in time with query performance counter.
// time.Time on Windows has low system granularity, which is not suitable for
// measuring short time intervals.
//
// TODO: If Windows runtime implements high resolution timing then highPrecisionTime
// can be removed.
type highPrecisionTime struct {
	now int64
}

// highPrecisionTimeNow returns high precision time for benchmarking.
func highPrecisionTimeNow() highPrecisionTime {
	var t highPrecisionTime
	// This should always succeed for Windows XP and above.
	t.now = windows.QueryPerformanceCounter()
	return t
}

func (a highPrecisionTime) sub(b highPrecisionTime) time.Duration {
	delta := a.now - b.now
	if delta < 0 {
		// QueryPerformanceCounter is not guaranteed to agree between processors
		// on Windows XP, where it is read from each core's TSC. A goroutine
		// that migrates between cores can therefore see the counter run
		// backwards. Measured on XP SP3: `go test os` panics partway through,
		// because a negative delta becomes a near-2^64 unsigned one and
		// bits.Div64 overflows its quotient.
		//
		// Reporting no elapsed time is a better answer than a panic, and on a
		// machine whose counter really is monotonic this branch never runs.
		return 0
	}

	if queryPerformanceFrequency == 0 {
		queryPerformanceFrequency = windows.QueryPerformanceFrequency()
		if queryPerformanceFrequency == 0 {
			// bits.Div64 panics on a zero divisor. There is nothing to scale
			// by, so report no elapsed time, as above.
			return 0
		}
	}
	hi, lo := bits.Mul64(uint64(delta), uint64(time.Second)/uint64(time.Nanosecond))
	if hi >= uint64(queryPerformanceFrequency) {
		// The same disagreement between per-core counters as above, in the
		// other direction: a goroutine can also migrate onto a core whose TSC
		// is far ahead, making delta enormous rather than negative. bits.Div64
		// panics when y <= hi, and a quotient that large means more than 2^64
		// nanoseconds - about 584 years - so this is a bad reading and not a
		// long interval.
		return 0
	}
	quo, _ := bits.Div64(hi, lo, uint64(queryPerformanceFrequency))
	return time.Duration(quo)
}

var queryPerformanceFrequency int64

// highPrecisionTimeSince returns duration since a.
func highPrecisionTimeSince(a highPrecisionTime) time.Duration {
	return highPrecisionTimeNow().sub(a)
}
