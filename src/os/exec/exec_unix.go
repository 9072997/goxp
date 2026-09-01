// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !plan9 && !windows

package exec

import (
	"io"
	"io/fs"
	"syscall"
)

// dontInheritPipes is a no-op here. Handle inheritance is a Windows concept;
// on this platform the child's file descriptors are exactly those passed to
// StartProcess.
func dontInheritPipes(pipes []io.Closer) {}

// skipStdinCopyError optionally specifies a function which reports
// whether the provided stdin copy error should be ignored.
func skipStdinCopyError(err error) bool {
	// Ignore EPIPE errors copying to stdin if the program
	// completed successfully otherwise.
	// See Issue 9173.
	pe, ok := err.(*fs.PathError)
	return ok &&
		pe.Op == "write" && pe.Path == "|1" &&
		pe.Err == syscall.EPIPE
}
