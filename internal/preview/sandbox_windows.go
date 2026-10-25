//go:build windows

package preview

import "os/exec"

// isolate: on Windows exec.CommandContext's default Cancel kills only the process itself.
// ponytail: no job objects; the worker runs only on Linux, Windows is for dev builds/tests.
func isolate(*exec.Cmd) {}

func reap(*exec.Cmd) {}
