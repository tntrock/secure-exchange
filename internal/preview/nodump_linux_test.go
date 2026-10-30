package preview

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckTmpfs(t *testing.T) {
	if _, err := os.Stat("/dev/shm"); err != nil {
		t.Skip("no /dev/shm")
	}
	if err := CheckTmpfs("/dev/shm"); err != nil {
		t.Fatal(err)
	}
	wd, _ := os.Getwd() // the source tree is on a disk, not a tmpfs
	if err := CheckTmpfs(wd); err == nil {
		t.Fatal("source dir accepted as tmpfs")
	}
	if err := CheckTmpfs(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing dir accepted")
	}
}
