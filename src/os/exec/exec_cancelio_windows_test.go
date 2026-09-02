// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package exec_test

import "internal/syscall/windows"

// canCancelPendingIO reports whether a read or write already in progress can be
// cancelled from another goroutine. Before Windows Vista there is no
// CancelIoEx, and CancelIo reaches only operations issued by the calling
// thread - which, for a thread parked inside ReadFile, is no help at all.
func canCancelPendingIO() bool { return windows.SupportCancelIoEx() }
