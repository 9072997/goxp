// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os_test

import "internal/syscall/windows"

// canCancelPendingIO reports whether a blocking read or write already in
// progress can be cancelled from another goroutine. Before Windows Vista there
// is no CancelIoEx, and CancelIo reaches only operations issued by the calling
// thread, so an operation another goroutine is parked in cannot be reached at
// all.
func canCancelPendingIO() bool { return windows.SupportCancelIoEx() }

// canStatConsoleAlias reports whether the \\.\ form of a console device name
// can be opened. Before Vista, CreateFile refuses \\.\CONIN$ and \\.\CONOUT$
// with ERROR_FILE_NOT_FOUND whatever access is asked for, so there is no route
// by which os.Stat could describe them. Plain CONIN$ and CONOUT$, and both
// forms of CON, do work there.
func canStatConsoleAlias() bool { return windows.SupportDeviceNamesInFileAPIs() }
