package runner

import (
	"os/exec"
	"syscall"
)

// setParentDeathSignal makes the kernel SIGKILL cmd's process as soon
// as the thread that started it exits. A host program's run locks are
// often flocks the kernel drops when it dies, so without this a SIGKILLed
// host program could leave a child still working while the next sweep,
// seeing the lock free, starts a second run. Pdeathsig is tied to the
// starting OS thread, not the process: Pipeline locks its goroutine to
// that thread until every stage is reaped.
func setParentDeathSignal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
