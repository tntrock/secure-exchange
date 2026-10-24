package sxcrypto

// SetAfterPass installs the RotateAll per-pass hook for tests.
func SetAfterPass(f func(int)) { afterPass = f }
