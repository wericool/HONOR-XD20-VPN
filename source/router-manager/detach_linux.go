//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

// Workers must survive the CGI/Telnet parent's exit with only their private log.
func adapterDetach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
