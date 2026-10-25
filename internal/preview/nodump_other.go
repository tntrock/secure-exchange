//go:build !linux

package preview

// NoDump is a no-op off Linux; the worker only runs in its Linux container.
func NoDump() error { return nil }

// CheckTmpfs is a no-op off Linux.
func CheckTmpfs(string) error { return nil }
