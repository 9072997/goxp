// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows

package os_test

// canCancelPendingIO reports whether a blocking read or write already in
// progress can be cancelled from another goroutine. Everywhere but old Windows
// closing the descriptor is enough to interrupt it.
func canCancelPendingIO() bool { return true }
