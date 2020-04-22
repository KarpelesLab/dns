package main

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func udpControl(network, address string, c syscall.RawConn) error {
	var err error

	err2 := c.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
	})

	if err2 != nil {
		return err2
	}
	return err
}
