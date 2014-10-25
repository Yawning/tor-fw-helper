// Copyright (c) 2014, The Tor Project, Inc.
// See LICENSE for licensing information

package natpmp

import (
	"net"
	"syscall"
	"unsafe"
)

var iphlpapi = syscall.NewLazyDLL("Iphlpapi.dll")
var procGetBestRoute = iphlpapi.NewProc("GetBestRoute")

// mibIPForwardRow is MIBIPFORWARDROW from windows.
type mibIPForwardRow struct {
	dwForwardDest      uint32
	dwForwardMask      uint32
	dwForwardPolicy    uint32
	dwForwardNextHop   uint32
	dwForwardIfIndex   uint32
	dwForwardType      uint32
	dwForwardProto     uint32
	dwForwardAge       uint32
	dwForwardNextHopAS uint32
	dwForwardMetric1   uint32
	dwForwardMetric2   uint32
	dwForwardMetric3   uint32
	dwForwardMetric4   uint32
	dwForwardMetric5   uint32
}

func getGateway() (net.IP, error) {
	// This routine uses "unsafe".  Yolo, swag, 420 blaze it.
	if err := iphlpapi.Load(); err != nil {
		return nil, err
	}
	if err := procGetBestRoute.Find(); err != nil {
		return nil, err
	}

	var dwDestAddr, dwSourceAddr uintptr // 0.0.0.0
	row := mibIPForwardRow{}
	r0, _, e1 := syscall.Syscall(procGetBestRoute.Addr(), 3, dwDestAddr, dwSourceAddr, uintptr(unsafe.Pointer(&row)))
	if r0 != 0 { // r0 != NO_ERROR
		return nil, e1
	}

	// Ok, row should have what windows thinks is the best route to "0.0.0.0"
	// now, which will be the default gateway, per the documentation this is in
	// network byte order.  Assume host byte order is little endian because
	// this is windows.
	a := row.dwForwardNextHop
	return net.IPv4(byte(a), byte(a >> 8), byte(a >> 16), byte(a >> 24)), nil
}
