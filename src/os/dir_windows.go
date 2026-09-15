// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package os

import (
	"internal/syscall/windows"
	"io"
	"io/fs"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// Auxiliary information if the File describes a directory
type dirInfo struct {
	mu sync.Mutex
	// buf is a slice pointer so the slice header
	// does not escape to the heap when returning
	// buf to dirBufPool.
	buf   *[]byte // buffer for directory I/O
	bufp  int     // location of next record in buf
	h     syscall.Handle
	vol   uint32
	class uint32 // type of entries in buf
	path  string // absolute directory path, empty if the file system supports FILE_ID_BOTH_DIR_INFO

	// reader is how entries are being read. It starts as
	// GetFileInformationByHandleEx and moves on only if that cannot be used.
	reader dirReader

	// State for the NtQueryDirectoryFile reader. See readDirNtQuery.
	ntHandle   syscall.Handle // handle the query is issued on: h, or a synchronous reopening of it
	ntReopened bool           // ntHandle is a reopening of h, and closed with the dirInfo
	ntStarted  bool           // a query has succeeded since the scan was last restarted
	ntEOF      bool           // the scan is finished
	ntPos      int            // entries, . and .. excluded, this listing has returned
	ntSeen     int            // entries, . and .. excluded, the scan has returned since it last restarted

	// State for the FindFirstFile/FindNextFile reader, the last resort. The
	// search has to persist across readdir calls so that a bounded Readdir(n)
	// makes forward progress instead of restarting from the first entry.
	findHandle  syscall.Handle // FindFirstFile handle, 0 if no search is open
	findData    syscall.Win32finddata
	findPending bool // findData holds an entry that has not been returned yet
	findEOF     bool // the search is finished
}

// dirReader identifies the call File.readdir reads a directory with.
type dirReader uint8

const (
	// dirReaderInfoEx is GetFileInformationByHandleEx, Vista and later.
	dirReaderInfoEx dirReader = iota
	// dirReaderNtQuery is NtQueryDirectoryFile on the directory's handle.
	dirReaderNtQuery
	// dirReaderFindFirstFile is FindFirstFile/FindNextFile on the
	// directory's name.
	dirReaderFindFirstFile
)

const (
	// dirBufSize is the size of the dirInfo buffer.
	// The buffer must be big enough to hold at least a single entry.
	// The filename alone can be 512 bytes (MAX_PATH*2), and the fixed part of
	// the FILE_ID_BOTH_DIR_INFO structure is 105 bytes, so dirBufSize
	// should not be set below 1024 bytes (512+105+safety buffer).
	// Windows 8.1 and earlier only works with buffer sizes up to 64 kB.
	dirBufSize = 64 * 1024 // 64kB

	// maxNtQueryBufSize bounds how far readDirNtQuery grows its buffer when a
	// single entry does not fit. The largest entry a name can produce is the
	// 94-byte fixed part plus a 65535-byte name, so this is never reached by
	// a file system that is telling the truth.
	maxNtQueryBufSize = 1 << 20
)

var dirBufPool = sync.Pool{
	New: func() any {
		// The buffer must be at least a block long.
		buf := make([]byte, dirBufSize)
		return &buf
	},
}

// releaseBuf drops d.buf, returning it to dirBufPool if it came from there.
func (d *dirInfo) releaseBuf() {
	if d.buf != nil {
		if len(*d.buf) == dirBufSize {
			dirBufPool.Put(d.buf)
		}
		d.buf = nil
	}
}

func (d *dirInfo) close() {
	d.h = 0
	d.releaseBuf()
	d.closeNtHandle()
	if d.findHandle != 0 {
		syscall.FindClose(d.findHandle)
		d.findHandle = 0
	}
	d.findPending = false
	d.findEOF = false
}

func (d *dirInfo) closeNtHandle() {
	if d.ntReopened {
		syscall.CloseHandle(d.ntHandle)
	}
	d.ntHandle = 0
	d.ntReopened = false
}

// allowReadDirFileID indicates whether File.readdir should try to use FILE_ID_BOTH_DIR_INFO
// if the underlying file system supports it.
// Useful for testing purposes.
var allowReadDirFileID = true

// readDirPreVista makes File.readdir behave as it does on a Windows without
// GetFileInformationByHandleEx and GetVolumeInformationByHandleW, which is to
// say Windows XP, whatever Windows it is running on. For testing.
var readDirPreVista = false

// readDirNtQueryBufSize is the size of the buffer readDirNtQuery starts with.
// Tests shrink it to make entries overflow it.
var readDirNtQueryBufSize = dirBufSize

// fileFullDirInfoUnsupported starts every directory on
// FileIdBothDirectoryRestartInfo, as readdir does for one directory once the
// kernel has rejected FileFullDirectoryRestartInfo. Useful for testing
// purposes.
var fileFullDirInfoUnsupported = false

func (d *dirInfo) init(h syscall.Handle) {
	d.h = h
	d.class = windows.FileFullDirectoryRestartInfo
	if fileFullDirInfoUnsupported {
		d.class = windows.FileIdBothDirectoryRestartInfo
	}
	// The previous settings are enough to read the directory entries.
	// The following code is only needed to support os.SameFile.

	// It is safe to query d.vol once and reuse the value.
	// Hard links are not allowed to reference files in other volumes.
	// Junctions and symbolic links can reference files and directories in other volumes,
	// but the reparse point should still live in the parent volume.
	var flags uint32
	var err error = windows.ERROR_NOT_SUPPORTED
	if !readDirPreVista {
		err = windows.GetVolumeInformationByHandle(h, nil, 0, &d.vol, nil, &flags, nil, 0)
	}
	if err == windows.ERROR_NOT_SUPPORTED {
		// Pre-Vista: GetVolumeInformationByHandleW does not exist here. Both
		// things it was asked for are still obtainable. The volume serial is in
		// GetFileInformationByHandle, which is XP-era. The flags only choose
		// between the file-ID route and the path route below, and the file-ID
		// route is Vista+ as well, so the path route is the only candidate and
		// the flags need not be read at all.
		//
		// Returning early here instead would leave every entry with a zero
		// volume and no path, which does not merely disable os.SameFile - it
		// makes it answer wrongly in both directions, since two entries that
		// are both zero compare equal and an entry never matches its own Stat.
		var i syscall.ByHandleFileInformation
		if err := syscall.GetFileInformationByHandle(h, &i); err != nil {
			d.vol = 0
			return
		}
		d.vol = i.VolumeSerialNumber
		d.path, _ = windows.FinalPath(h, windows.FILE_NAME_OPENED)
		return
	}
	if err != nil {
		d.vol = 0 // Set to zero in case Windows writes garbage to it.
		// If we can't get the volume information, we can't use os.SameFile,
		// but we can still read the directory entries.
		return
	}
	if flags&windows.FILE_SUPPORTS_OBJECT_IDS == 0 {
		// The file system does not support object IDs, no need to continue.
		return
	}
	if allowReadDirFileID && flags&windows.FILE_SUPPORTS_OPEN_BY_FILE_ID != 0 {
		// Use FileIdBothDirectoryRestartInfo if available as it returns the file ID
		// without the need to open the file.
		d.class = windows.FileIdBothDirectoryRestartInfo
	} else {
		// If FileIdBothDirectoryRestartInfo is not available but objects IDs are supported,
		// get the directory path so that os.SameFile can use it to open the file
		// and retrieve the file ID.
		d.path, _ = windows.FinalPath(h, windows.FILE_NAME_OPENED)
	}
}

func (file *File) readdir(n int, mode readdirMode) (names []string, dirents []DirEntry, infos []FileInfo, err error) {
	// If this file has no dirInfo, create one.
	var d *dirInfo
	for {
		d = file.dirinfo.Load()
		if d != nil {
			break
		}
		d = new(dirInfo)
		d.init(file.pfd.Sysfd)
		if file.dirinfo.CompareAndSwap(nil, d) {
			break
		}
		// We lost the race: try again.
		d.close()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.buf == nil {
		d.buf = dirBufPool.Get().(*[]byte)
	}

	wantAll := n <= 0
	if wantAll {
		n = -1
	}
	if readDirPreVista && d.reader == dirReaderInfoEx {
		d.reader = dirReaderNtQuery
	}
	switch d.reader {
	case dirReaderNtQuery:
		return readDirNtQuery(file, d, n, wantAll, mode)
	case dirReaderFindFirstFile:
		d.releaseBuf()
		return readDirFindFirstFile(file, n, wantAll, mode)
	}
	for n != 0 {
		// Refill the buffer if necessary
		if d.bufp == 0 {
			err = windows.GetFileInformationByHandleEx(file.pfd.Sysfd, d.class, (*byte)(unsafe.Pointer(&(*d.buf)[0])), uint32(len(*d.buf)))
			runtime.KeepAlive(file)
			if err != nil {
				if err == syscall.ERROR_NO_MORE_FILES {
					// Optimization: we can return the buffer to the pool, there is nothing else to read.
					dirBufPool.Put(d.buf)
					d.buf = nil
					break
				}
				if err == windows.ERROR_INVALID_PARAMETER && d.class == windows.FileFullDirectoryRestartInfo {
					// This kernel does not know FILE_FULL_DIR_INFO, which
					// every Windows before 8 lacks. Read this directory
					// with the class it does know, which carries every
					// field readdir uses.
					d.class = windows.FileIdBothDirectoryRestartInfo
					continue
				}
				if err == syscall.ERROR_FILE_NOT_FOUND &&
					(d.class == windows.FileIdBothDirectoryRestartInfo || d.class == windows.FileFullDirectoryRestartInfo) {
					// GetFileInformationByHandleEx doesn't document the return error codes when the info class is FileIdBothDirectoryRestartInfo,
					// but MS-FSA 2.1.5.6.3 [1] specifies that the underlying file system driver should return STATUS_NO_SUCH_FILE when
					// reading an empty root directory, which is mapped to ERROR_FILE_NOT_FOUND by Windows.
					// Note that some file system drivers may never return this error code, as the spec allows to return the "." and ".."
					// entries in such cases, making the directory appear non-empty.
					// The chances of false positive are very low, as we know that the directory exists, else GetVolumeInformationByHandle
					// would have failed, and that the handle is still valid, as we haven't closed it.
					// See go.dev/issue/61159.
					// [1] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/fa8194e0-53ec-413b-8315-e8fa85396fd8
					break
				}
				if (err == windows.ERROR_INVALID_PARAMETER || err == windows.ERROR_NOT_SUPPORTED) &&
					(d.class == windows.FileFullDirectoryRestartInfo || d.class == windows.FileFullDirectoryInfo ||
						d.class == windows.FileIdBothDirectoryRestartInfo) {
					// GetFileInformationByHandleEx is Vista and later, and this
					// fork's binding reports its absence as ERROR_NOT_SUPPORTED,
					// so on Windows XP this is the first call's answer. A file
					// system can also refuse both directory classes this
					// reader knows. Either way, read the directory with the
					// native call instead, from the same handle.
					d.reader = dirReaderNtQuery
					if d.path == "" {
						// The FILE_ID_BOTH_DIR_INFO route leaves the path
						// unset, and os.SameFile needs it for these entries.
						d.path, _ = windows.FinalPath(d.h, windows.FILE_NAME_OPENED)
					}
					return readDirNtQuery(file, d, n, wantAll, mode)
				}
				if s, _ := file.Stat(); s != nil && !s.IsDir() {
					err = &PathError{Op: "readdir", Path: file.name, Err: syscall.ENOTDIR}
				} else {
					err = &PathError{Op: "GetFileInformationByHandleEx", Path: file.name, Err: err}
				}
				return
			}
			if d.class == windows.FileIdBothDirectoryRestartInfo {
				d.class = windows.FileIdBothDirectoryInfo
			} else if d.class == windows.FileFullDirectoryRestartInfo {
				d.class = windows.FileFullDirectoryInfo
			}
		}
		// Drain the buffer
		var islast bool
		for n != 0 && !islast {
			var nextEntryOffset uint32
			var nameslice []uint16
			entry := unsafe.Pointer(&(*d.buf)[d.bufp])
			if d.class == windows.FileIdBothDirectoryInfo {
				info := (*windows.FILE_ID_BOTH_DIR_INFO)(entry)
				nextEntryOffset = info.NextEntryOffset
				nameslice = unsafe.Slice(&info.FileName[0], info.FileNameLength/2)
			} else {
				info := (*windows.FILE_FULL_DIR_INFO)(entry)
				nextEntryOffset = info.NextEntryOffset
				nameslice = unsafe.Slice(&info.FileName[0], info.FileNameLength/2)
			}
			d.bufp += int(nextEntryOffset)
			islast = nextEntryOffset == 0
			if islast {
				d.bufp = 0
			}
			if (len(nameslice) == 1 && nameslice[0] == '.') ||
				(len(nameslice) == 2 && nameslice[0] == '.' && nameslice[1] == '.') {
				// Ignore "." and ".." and avoid allocating a string for them.
				continue
			}
			name := syscall.UTF16ToString(nameslice)
			if mode == readdirName {
				names = append(names, name)
			} else {
				var f *fileStat
				if d.class == windows.FileIdBothDirectoryInfo {
					f = newFileStatFromFileIDBothDirInfo((*windows.FILE_ID_BOTH_DIR_INFO)(entry))
				} else {
					f = newFileStatFromFileFullDirInfo((*windows.FILE_FULL_DIR_INFO)(entry))
					if d.path != "" {
						// Defer appending the entry name to the parent directory path until
						// it is really needed, to avoid allocating a string that may not be used.
						// It is currently only used in os.SameFile.
						f.appendNameToPath = true
						f.path = d.path
					}
				}
				f.name = name
				f.vol = d.vol
				if mode == readdirDirEntry {
					dirents = append(dirents, dirEntry{f})
				} else {
					infos = append(infos, f)
				}
			}
			n--
		}
	}
	if !wantAll && len(names)+len(dirents)+len(infos) == 0 {
		return nil, nil, nil, io.EOF
	}
	return names, dirents, infos, nil
}

// readDirNtQuery reads directory entries with NtQueryDirectoryFile and
// FileBothDirectoryInformation, from the directory's handle.
//
// It is used where GetFileInformationByHandleEx is missing (Windows XP) or
// refuses FileFullDirectoryRestartInfo (very old SMB shares). What matters is
// that it lists the directory the handle refers to. A reader that resolves the
// directory again by name, as FindFirstFile does, lists whatever is at that
// name now: a directory renamed away and replaced by a junction is listed
// through the junction, even though the handle - and an os.Root holding it -
// still refers to the original.
//
// FileBothDirectoryInformation is the class FindFirstFileW and FindNextFileW
// are built on, so every file system they could list answers it, and every
// field WIN32_FIND_DATAW carried comes from the same bytes here: attributes,
// the three times, the size, and, for a reparse point, the reparse tag in
// EaSize.
//
// The handle's scan position lives in the kernel's file object, so the first
// query restarts the scan and later ones continue it, and a bounded Readdir(n)
// makes forward progress across calls. The caller must hold d.mu.
func readDirNtQuery(file *File, d *dirInfo, n int, wantAll bool, mode readdirMode) (names []string, dirents []DirEntry, infos []FileInfo, err error) {
	if d.ntHandle == 0 {
		d.ntHandle = d.h
		if nonblocking, _ := windows.IsNonblock(d.h); nonblocking {
			// Opened with FILE_FLAG_OVERLAPPED: a query on this handle would
			// return STATUS_PENDING and complete on the I/O completion port.
			// List through a synchronous handle to the same directory instead.
			h, e := windows.ReopenDirectoryForListing(d.h)
			runtime.KeepAlive(file)
			if e != nil {
				d.ntHandle = 0
				return nil, nil, nil, &PathError{Op: "readdir", Path: file.name, Err: e}
			}
			d.ntHandle = h
			d.ntReopened = true
		}
		if d.buf != nil && len(*d.buf) != readDirNtQueryBufSize {
			d.releaseBuf()
			buf := make([]byte, readDirNtQueryBufSize)
			d.buf = &buf
		}
	}

	for n != 0 {
		// Refill the buffer if necessary
		if d.bufp == 0 {
			if d.ntEOF {
				break
			}
			if d.buf == nil {
				d.buf = dirBufPool.Get().(*[]byte)
			}
			restart := !d.ntStarted
			var iosb windows.IO_STATUS_BLOCK
			st := windows.NtQueryDirectoryFile(d.ntHandle, 0, 0, 0, &iosb,
				unsafe.Pointer(&(*d.buf)[0]), uint32(len(*d.buf)),
				windows.FileBothDirectoryInformation, false, nil, restart)
			runtime.KeepAlive(file)
			switch {
			case st == nil:
				d.ntStarted = true
				if iosb.Information == 0 {
					// Success with nothing in the buffer. Not something a file
					// system should say, but treating it as the end is the only
					// answer that cannot loop forever.
					d.ntEOF = true
					d.releaseBuf()
					continue
				}

			case st == windows.STATUS_NO_MORE_FILES,
				st == windows.STATUS_NO_SUCH_FILE && restart:
				// STATUS_NO_SUCH_FILE is what the first query of a directory
				// with no entries at all returns; a directory normally reports
				// "." and "..", so this is rare, but it is empty, not an error.
				d.ntEOF = true
				d.releaseBuf()
				continue

			case st == windows.STATUS_BUFFER_OVERFLOW, st == windows.STATUS_INFO_LENGTH_MISMATCH:
				// Not even one entry fit. The buffer now holds a truncated
				// entry, and whether the scan has moved past it is up to the
				// file system. So grow the buffer and restart the scan, and let
				// the drain loop discard the entries this listing has already
				// returned. With the 64 kB buffer this takes a name longer than
				// any file system allows, so in practice it never happens.
				size := 2 * len(*d.buf)
				if size > maxNtQueryBufSize {
					err = &PathError{Op: "NtQueryDirectoryFile", Path: file.name, Err: st.(windows.NTStatus).Errno()}
					return
				}
				d.releaseBuf()
				buf := make([]byte, size)
				d.buf = &buf
				d.ntStarted = false
				d.ntSeen = 0
				continue

			default:
				if s, _ := file.Stat(); s != nil && !s.IsDir() {
					err = &PathError{Op: "readdir", Path: file.name, Err: syscall.ENOTDIR}
					return
				}
				if restart && d.ntPos == 0 && (st == windows.STATUS_INVALID_INFO_CLASS ||
					st == windows.STATUS_INVALID_PARAMETER ||
					st == windows.STATUS_NOT_SUPPORTED ||
					st == windows.STATUS_NOT_IMPLEMENTED) {
					// The file system will not list this directory by handle at
					// all, and nothing has been returned yet. The only reader
					// left is the one that resolves the directory by name.
					d.closeNtHandle()
					d.releaseBuf()
					d.reader = dirReaderFindFirstFile
					return readDirFindFirstFile(file, n, wantAll, mode)
				}
				e := st
				if s, ok := st.(windows.NTStatus); ok {
					e = s.Errno()
				}
				err = &PathError{Op: "NtQueryDirectoryFile", Path: file.name, Err: e}
				return
			}
		}
		// Drain the buffer
		var islast bool
		for n != 0 && !islast {
			entry := (*windows.FILE_BOTH_DIR_INFORMATION)(unsafe.Pointer(&(*d.buf)[d.bufp]))
			d.bufp += int(entry.NextEntryOffset)
			islast = entry.NextEntryOffset == 0
			if islast {
				d.bufp = 0
			}
			nameslice := unsafe.Slice(&entry.FileName[0], entry.FileNameLength/2)
			if (len(nameslice) == 1 && nameslice[0] == '.') ||
				(len(nameslice) == 2 && nameslice[0] == '.' && nameslice[1] == '.') {
				// Ignore "." and ".." and avoid allocating a string for them.
				// They are not counted in ntSeen and ntPos either, because
				// they do not come back reliably: measured on NTFS, a buffer
				// with room for one entry returns "." and then skips "..".
				continue
			}
			d.ntSeen++
			if d.ntSeen <= d.ntPos {
				// Returned before the scan was restarted.
				continue
			}
			d.ntPos++
			name := syscall.UTF16ToString(nameslice)
			if mode == readdirName {
				names = append(names, name)
			} else {
				f := newFileStatFromFileBothDirInformation(entry)
				f.name = name
				f.vol = d.vol
				if d.path != "" {
					// Defer appending the entry name to the parent directory
					// path until it is really needed, as os.SameFile does.
					f.appendNameToPath = true
					f.path = d.path
				}
				if mode == readdirDirEntry {
					dirents = append(dirents, dirEntry{f})
				} else {
					infos = append(infos, f)
				}
			}
			n--
		}
	}
	if !wantAll && len(names)+len(dirents)+len(infos) == 0 {
		return nil, nil, nil, io.EOF
	}
	return names, dirents, infos, nil
}

// readDirFindFirstFile reads directory entries with the legacy
// FindFirstFile/FindNextFile API.
//
// It resolves the directory by name rather than by handle, so it is used only
// where the file system refuses to list the directory by handle at all: see
// readDirNtQuery.
//
// The search handle is kept in dirInfo, so successive calls continue where the
// previous one stopped. The caller must hold d.mu.
func readDirFindFirstFile(file *File, n int, wantAll bool, mode readdirMode) (names []string, dirents []DirEntry, infos []FileInfo, err error) {
	d := file.dirinfo.Load()

	if d.findHandle == 0 && !d.findEOF {
		// Build the search pattern, following the same rules as the
		// pre-Go 1.22 implementation of this function.
		path := fixLongPath(file.name)
		var mask string
		switch {
		case len(path) == 2 && path[1] == ':': // a drive letter, like C:
			mask = path + `*`
		case len(path) == 0:
			mask = `\*`
		case path[len(path)-1] == '/' || path[len(path)-1] == '\\':
			mask = path + `*`
		default:
			mask = path + `\*`
		}
		maskp, e := syscall.UTF16PtrFromString(mask)
		if e != nil {
			return nil, nil, nil, &PathError{Op: "readdir", Path: file.name, Err: e}
		}
		h, e := syscall.FindFirstFile(maskp, &d.findData)
		switch e {
		case nil:
			d.findHandle = h
			d.findPending = true
		case syscall.ERROR_FILE_NOT_FOUND, syscall.ERROR_NO_MORE_FILES:
			// The directory exists but has no entries at all. Note that a
			// directory normally reports "." and "..", so this is rare.
			d.findEOF = true
		default:
			return nil, nil, nil, &PathError{Op: "FindFirstFile", Path: file.name, Err: e}
		}
	}

	for n != 0 && !d.findEOF {
		if !d.findPending {
			if e := syscall.FindNextFile(d.findHandle, &d.findData); e != nil {
				if e == syscall.ERROR_NO_MORE_FILES {
					d.findEOF = true
					break
				}
				return names, dirents, infos, &PathError{Op: "FindNextFile", Path: file.name, Err: e}
			}
		}
		d.findPending = false

		name := syscall.UTF16ToString(d.findData.FileName[:])
		if name == "." || name == ".." { // Useless names
			continue
		}
		if mode == readdirName {
			names = append(names, name)
		} else {
			f := newFileStatFromWin32finddata(&d.findData)
			f.name = name
			f.vol = d.vol
			if d.path != "" {
				// Defer appending the entry name to the parent directory
				// path until it is really needed, as os.SameFile does.
				f.appendNameToPath = true
				f.path = d.path
			}
			if mode == readdirDirEntry {
				dirents = append(dirents, dirEntry{f})
			} else {
				infos = append(infos, f)
			}
		}
		n--
	}

	if !wantAll && len(names)+len(dirents)+len(infos) == 0 {
		return nil, nil, nil, io.EOF
	}
	return names, dirents, infos, nil
}

type dirEntry struct {
	fs *fileStat
}

func (de dirEntry) Name() string            { return de.fs.Name() }
func (de dirEntry) IsDir() bool             { return de.fs.IsDir() }
func (de dirEntry) Type() FileMode          { return de.fs.Mode().Type() }
func (de dirEntry) Info() (FileInfo, error) { return de.fs, nil }

func (de dirEntry) String() string {
	return fs.FormatDirEntry(de)
}
