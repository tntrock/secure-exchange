//go:build linux

package preview

import "golang.org/x/sys/unix"

// NoDump makes this process non-dumpable, so same-uid children (LibreOffice
// following a file:// link in a hostile document) cannot read /proc/<pid>/environ
// or /proc/<pid>/mem, which hold the master keys and database URL.
func NoDump() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
