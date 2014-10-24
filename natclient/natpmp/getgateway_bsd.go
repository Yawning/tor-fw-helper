// Copyright (c) 2014, The Tor Project, Inc.
// See LICENSE for licensing information

// +build dragonfly freebsd netbsd openbsd darwin

package natpmp

import (
	"fmt"
	"net"
	"syscall"
)

const (
	NET_RT_DUMP = 1 // From FreeBSD sys/socket.h
)

var defaultNet = net.IPv4(0, 0, 0, 0)

func getGateway() (net.IP, error) {
	// Ok, so the BSD version of the go runtime routing table dumo code is
	// a bit more limited than the Linux version, since again, getting the
	// message metadata is a huge pain.  This should work on all the BSDs
	// that are relevant.
	rib, err := syscall.RouteRIB(NET_RT_DUMP, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseRoutingMessage(rib)
	if err != nil {
		return nil, err
	}
	for _, msg := range msgs {
		sas, err := syscall.ParseRoutingSockaddr(msg)
		if err != nil {
			continue
		}
		if len(sas) < 2 {
			continue
		}

		var dstSa, gwSa *syscall.SockaddrInet4
		ok := false
		if dstSa, ok = sas[0].(*syscall.SockaddrInet4); !ok {
			continue
		}
		if gwSa, ok = sas[1].(*syscall.SockaddrInet4); !ok {
			continue
		}
		if dstSa == nil || gwSa == nil {
			continue
		}

		dstAddr := net.IPv4(dstSa.Addr[0], dstSa.Addr[1], dstSa.Addr[2], dstSa.Addr[3])
		gwAddr := net.IPv4(gwSa.Addr[0], gwSa.Addr[1], gwSa.Addr[2], gwSa.Addr[3])
		if dstAddr.Equal(defaultNet) {
			return gwAddr, nil
		}
	}
	return nil, fmt.Errorf("failed to find default gateway")
}
