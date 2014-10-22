/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

package natpmp

import (
	"fmt"
	"net"
	"syscall"
)

type tableEntry struct {
	srcAddr net.IP
	dstAddr net.IP
	gwAddr  net.IP
}

func routeToTableEntry(attrs []syscall.NetlinkRouteAttr) (*tableEntry, error) {
	var e tableEntry
	for _, attr := range attrs {
		// The routing attributes are Key/Length/Value, so cut the value
		// down to the length before figuring out what it is.  Note: IPv4
		// addresses are actually shorter than Attr.Len, but the runtime's
		// attribute parser doesn't let me easily get at RtMsg.  This will need
		// to be handled if we ever care about IPv6 (so basically never).
		v := attr.Value[:attr.Attr.Len]
		switch attr.Attr.Type {
		case syscall.RTA_DST:
			// Route destination address.
			if len(v) < net.IPv4len {
				return nil, syscall.ERANGE
			}
			e.dstAddr = net.IPv4(v[0], v[1], v[2], v[3])
		case syscall.RTA_SRC:
			// Route source address.
			if len(v) < net.IPv4len {
				return nil, syscall.ERANGE
			}
			e.srcAddr = net.IPv4(v[0], v[1], v[2], v[3])
		case syscall.RTA_GATEWAY:
			// The gateway of the route.
			if len(v) < net.IPv4len {
				return nil, syscall.ERANGE
			}
			e.gwAddr = net.IPv4(v[0], v[1], v[2], v[3])
		default:
			// Ignore RTA_<bleah> when it doesn't help us get what we want, not
			// an error since the attributes include things like the
			// interface/priority etc.
		}
	}
	return &e, nil
}

func getGateway() (net.IP, error) {
	// Yay, syscall has support for netlink(7) sockets.  Query the routing
	// table, and find the default route, it'll be the RTM_NEWROUTE message
	// without a destination address (ie: 0.0.0.0) and a gateway set.
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	rtTable := make([]*tableEntry, 0, len(msgs))
msgLoop:
	for _, msg := range msgs {
		switch msg.Header.Type {
		case syscall.NLMSG_DONE:
			break msgLoop
		case syscall.RTM_NEWROUTE:
			route, err := syscall.ParseNetlinkRouteAttr(&msg)
			if err != nil {
				return nil, err
			}
			e, err := routeToTableEntry(route)
			if err != nil {
				return nil, err
			}
			rtTable = append(rtTable, e)
		default:
			// WTF?  This should never happen, so silently ignore it and pray
			// that we get something sensible.
		}
	}

	// Find the default gateway in the routing table we just assembled.  Could
	// do this as we go instead of waiting till the entire table has been
	// parsed, but that doesn't save much time, and this is easier to debug.
	for _, e := range rtTable {
		if e.dstAddr == nil && e.gwAddr != nil {
			return e.gwAddr, nil
		}
	}

	return nil, fmt.Errorf("failed to find default gateway")
}
