// Copyright (c) 2014, The Tor Project, Inc.
// See LICENSE for licensing information

// +build !linux

package natpmp

import (
	"fmt"
	"net"
	"runtime"
)

func getGateway() (net.IP, error) {
	return nil, fmt.Errorf("getGateway not implemented on: %s", runtime.GOOS)
}
