// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package os

import (
	"io"
	"syscall"
)

// Root.RemoveAll for Windows.
//
// The package-level RemoveAll on Windows is the "noat" implementation in
// removeall_noat.go: it walks the tree by re-resolving paths by name.
// Root.RemoveAll cannot do that, because resolving a name against the
// filesystem namespace is exactly what Root exists to avoid.
//
// This is a handle-relative walk, in the style of the removeAllFrom in
// removeall_at.go, which Windows does not build. Every filesystem operation
// below is performed relative to an open directory handle using a single
// path component, so no operation can be redirected out of the root by a
// symlink or a "..".

func rootRemoveAll(r *Root, name string) error {
	// Consistency with os.RemoveAll: Strip trailing /s from the name,
	// so RemoveAll("not_a_directory/") succeeds.
	for len(name) > 0 && IsPathSeparator(name[len(name)-1]) {
		name = name[:len(name)-1]
	}
	if endsWithDot(name) {
		// Consistency with os.RemoveAll: Return EINVAL when trying to remove .
		return &PathError{Op: "RemoveAll", Path: name, Err: syscall.EINVAL}
	}
	_, err := doInRoot(r, name, 0, nil, func(parent sysfdType, base string, endsInSlash bool) (struct{}, error) {
		return struct{}{}, rootRemoveAllFrom(parent, base, joinPath(r.Name(), name))
	})
	if IsNotExist(err) {
		return nil
	}
	if underlyingError(err) == syscall.ENOTDIR {
		// Some intermediate path component is not a directory.
		// RemoveAll treats this as success, since the target cannot exist.
		// This matches the package-level RemoveAll on Windows.
		return nil
	}
	if err != nil {
		return &PathError{Op: "RemoveAll", Path: name, Err: underlyingError(err)}
	}
	return nil
}

// rootRemoveAllFrom removes the file or directory base, and any children it
// contains, from the directory referenced by parentFd.
//
// base is always a single path component: it is never "..", never contains a
// separator, and is resolved by the kernel relative to parentFd. The handles
// used to recurse are opened with O_NOFOLLOW_ANY, so a symlink encountered
// during the walk is deleted as a link rather than followed.
//
// path is the path of base as seen from the process's current directory.
// It is used for error messages, and to name the directory for the
// FindFirstFile fallback in File.readdir, which is what Windows versions
// without GetFileInformationByHandleEx (that is, Windows XP) list with.
// It is never used to open, delete, or otherwise resolve anything.
func rootRemoveAllFrom(parentFd sysfdType, base, path string) error {
	// Simple case: if the file can be removed, we're done.
	err := removefileat(parentFd, base)
	if err == nil || IsNotExist(err) {
		return nil
	}

	// EISDIR means that we have a directory, and we need to
	// remove its contents.
	// EPERM or EACCES means that we don't have write permission on
	// the parent directory, but this entry might still be a directory
	// whose contents need to be removed.
	// Otherwise just return the error.
	if err != syscall.EISDIR && err != syscall.EPERM && err != syscall.EACCES {
		return &PathError{Op: "unlinkat", Path: base, Err: err}
	}
	uErr := err

	// Remove the directory's entries.
	var recurseErr error
	for {
		const reqSize = 1024
		var respSize int

		// Open the directory to recurse into.
		file, err := rootOpenDirFile(parentFd, base, path)
		if err != nil {
			if IsNotExist(err) {
				return nil
			}
			if err == syscall.ENOTDIR {
				// Not a directory; return the error from the removefileat.
				return &PathError{Op: "unlinkat", Path: base, Err: uErr}
			}
			if _, ok := err.(errSymlink); ok {
				// base is a symlink to a directory.
				// Fall through to removedirat below, which deletes the
				// link itself rather than anything it points at.
				// Not a user-visible error.
				err = uErr
			}
			recurseErr = &PathError{Op: "openfdat", Path: base, Err: err}
			break
		}

		for {
			numErr := 0

			names, readErr := file.Readdirnames(reqSize)
			// Errors other than EOF should stop us from continuing.
			if readErr != nil && readErr != io.EOF {
				file.Close()
				if IsNotExist(readErr) {
					return nil
				}
				return &PathError{Op: "readdirnames", Path: base, Err: readErr}
			}

			respSize = len(names)
			for _, name := range names {
				err := rootRemoveAllFrom(sysfdType(file.Fd()), name, path+string(PathSeparator)+name)
				if err != nil {
					if pathErr, ok := err.(*PathError); ok {
						pathErr.Path = base + string(PathSeparator) + pathErr.Path
					}
					numErr++
					if recurseErr == nil {
						recurseErr = err
					}
				}
			}

			// If we can delete any entry, break to start new iteration.
			// Otherwise, we discard current names, get next entries and try deleting them.
			if numErr != reqSize {
				break
			}
		}

		// Removing files from the directory may have caused
		// the OS to reshuffle it. Simply calling Readdirnames
		// again may skip some entries. The only reliable way
		// to avoid this is to close and re-open the
		// directory. See issue 20841.
		file.Close()

		// Finish when the end of the directory is reached
		if respSize < reqSize {
			break
		}
	}

	// Remove the directory itself.
	unlinkError := removedirat(parentFd, base)
	if unlinkError == nil || IsNotExist(unlinkError) {
		return nil
	}

	if recurseErr != nil {
		return recurseErr
	}
	return &PathError{Op: "unlinkat", Path: base, Err: unlinkError}
}

// rootOpenDirFile opens the directory name relative to the directory handle
// dirfd, and wraps it in a *File named path.
//
// The open is handle-relative and refuses to follow a reparse point in name;
// path names the result only for the benefit of File.readdir's FindFirstFile
// fallback and of error messages.
//
// This acts like openFileNolog rather than OpenFile because
// we are going to (try to) remove the file.
// The contents of this file are not relevant for test caching.
func rootOpenDirFile(dirfd sysfdType, name, path string) (*File, error) {
	fd, err := rootOpenDir(dirfd, name)
	if err != nil {
		return nil, err
	}
	return newDirFile(fd, path)
}
