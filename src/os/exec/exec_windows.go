// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package exec

import (
	"io"
	"io/fs"
	"os"
	"syscall"
)

// dontInheritPipes clears HANDLE_FLAG_INHERIT on the parent's ends of the pipes
// this Cmd created, so a child cannot receive duplicates of them.
//
// It matters only before Vista, where there is no
// PROC_THREAD_ATTRIBUTE_HANDLE_LIST and CreateProcess therefore hands the child
// every inheritable handle in the process. syscall.Pipe makes both ends
// inheritable, so without this a child reading a pipe on stdin also holds the
// write end and never sees EOF - it waits for a close that its own handle
// prevents. On Vista and later the attribute list already excludes these, so
// clearing the flag changes nothing.
//
// Errors are ignored on purpose. Failing to clear the flag costs the hang this
// avoids; it is never worse than not trying, and there is nothing useful for a
// caller to do about it.
func dontInheritPipes(pipes []io.Closer) {
	for _, p := range pipes {
		if f, ok := p.(*os.File); ok {
			syscall.SetHandleInformation(syscall.Handle(f.Fd()), syscall.HANDLE_FLAG_INHERIT, 0)
		}
	}
}

// skipStdinCopyError optionally specifies a function which reports
// whether the provided stdin copy error should be ignored.
func skipStdinCopyError(err error) bool {
	// Ignore ERROR_BROKEN_PIPE and ERROR_NO_DATA errors copying
	// to stdin if the program completed successfully otherwise.
	// See Issue 20445.
	const _ERROR_NO_DATA = syscall.Errno(0xe8)
	pe, ok := err.(*fs.PathError)
	return ok &&
		pe.Op == "write" && pe.Path == "|1" &&
		(pe.Err == syscall.ERROR_BROKEN_PIPE || pe.Err == _ERROR_NO_DATA)
}
