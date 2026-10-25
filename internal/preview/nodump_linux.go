//go:build linux

package preview

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// NoDump makes this process non-dumpable, so same-uid children (LibreOffice
// following a file:// link in a hostile document) cannot read /proc/<pid>/environ
// or /proc/<pid>/mem, which hold the master keys and database URL.
func NoDump() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }

// CheckTmpfs fails unless dir is on a tmpfs, so decrypted plaintext stays off disk.
func CheckTmpfs(dir string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return err
	}
	if st.Type != unix.TMPFS_MAGIC {
		return fmt.Errorf("%s is not a tmpfs (f_type %#x)", dir, st.Type)
	}
	return nil
}
