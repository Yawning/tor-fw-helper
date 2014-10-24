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

type routeEntry struct {
	syscall.RtMsg
	SrcNet net.IPNet
	DstNet net.IPNet
	GwAddr net.IP
}

func parseRTMNewRoute(m *syscall.NetlinkMessage) (*routeEntry, error) {
	// The runtime doesn't expose RtMsg, which is needed to get the length of
	// various fields, so ensure that there is enough data present, and decode
	// the header by hand.
	if len(m.Data) < syscall.SizeofRtMsg {
		// Trunncated message.
		return nil, syscall.EINVAL
	}
	e := &routeEntry{}
	e.Family = m.Data[0]
	e.Dst_len = m.Data[1]
	e.Src_len = m.Data[2]
	e.Tos = m.Data[3]
	e.Table = m.Data[4]
	e.Protocol = m.Data[5]
	e.Scope = m.Data[6]
	e.Type = m.Data[7]
	e.Flags = uint32(m.Data[8]<<24) | uint32(m.Data[9]<<16) | uint32(m.Data[10]<<8) | uint32(m.Data[11])
	if e.Family != syscall.AF_INET {
		return nil, syscall.EAFNOSUPPORT
	}

	// Parse all the attributes associated with this routing table entry.
	attrs, err := syscall.ParseNetlinkRouteAttr(m)
	if err != nil {
		return nil, err
	}
	for _, a := range attrs {
		// Attr.Len is full of lies (not neccecarily 32 bits for AF_INET
		// addresses), but if the kernel is returning messages with the
		// incorrect address length when the family in the header is
		// AF_INET, there are bigger problems.
		v := a.Value[:a.Attr.Len]
		switch a.Attr.Type {
		case syscall.RTA_DST:
			// Route destination address.
			e.DstNet.Mask = net.CIDRMask(int(e.Dst_len), 32)
			e.DstNet.IP = net.IPv4(v[0], v[1], v[2], v[3])
		case syscall.RTA_SRC:
			// Route source address.
			e.SrcNet.Mask = net.CIDRMask(int(e.Src_len), 32)
			e.SrcNet.IP = net.IPv4(v[0], v[1], v[2], v[3])
		case syscall.RTA_GATEWAY:
			// The gateway of the route.
			e.GwAddr = net.IPv4(v[0], v[1], v[2], v[3])
		default:
			// Ignore RTA_<bleah> when it doesn't help us get what we want,
			// not an error since the attributes include things like the
			// interface/priority etc.
		}
	}
	return e, nil
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
	rtTable := make([]*routeEntry, 0, len(msgs))
msgLoop:
	for _, msg := range msgs {
		switch msg.Header.Type {
		case syscall.NLMSG_DONE:
			break msgLoop
		case syscall.RTM_NEWROUTE:
			route, err := parseRTMNewRoute(&msg)
			if err != nil {
				return nil, err
			}
			rtTable = append(rtTable, route)
		default:
			// WTF?  This should never happen, so silently ignore it and pray
			// that we get something sensible.
		}
	}

	// Find the default gateway in the routing table we just assembled.  Could
	// do this as we go instead of waiting till the entire table has been
	// parsed, but that doesn't save much time, and this is easier to debug.
	for _, e := range rtTable {
		if e.DstNet.IP == nil && e.GwAddr != nil {
			return e.GwAddr, nil
		}
	}
	return nil, fmt.Errorf("failed to find default gateway")
}
