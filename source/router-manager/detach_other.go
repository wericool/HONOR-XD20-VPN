//go:build !linux

package main

import "os/exec"

// Unit tests replace adapterSpawn and never launch a router worker on Windows.
func adapterDetach(cmd *exec.Cmd) {}
