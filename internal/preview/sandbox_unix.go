//go:build unix

package preview

import (
	"os/exec"
	"syscall"
)

// isolate puts the command in its own process group and makes cancellation kill the whole group.
func isolate(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// reap kills anything the command left running in its group (e.g. soffice.bin).
func reap(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // group may already be gone
	}
}
