/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

// Package upnp implements a simple UPnP client suitable for NAT traversal.
package upnp

import (
	"fmt"
	"net"
)

const (
//	userAgent = "BeOS/5.0 UPnP/1.1 Helper/1.0"
	userAgent = "" // Standardized, but optional.
	outgoingPort = 0
)

// Client is UPnP client instance.
type Client struct {
	ctrl         *controlPoint
	internalAddr *net.IP
}

// New creates a new UPnP client instance.
func New() (*Client, error) {
	var err error

	client := &Client{}
	client.ctrl, err = client.discover()
	if err != nil {
		return nil, err
	}
	client.internalAddr, err = client.getInternalAddress()
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (c *Client) getInternalAddress() (*net.IP, error) {
	// Since we bind to "0.0.0.0:port", we don't have our local address.
	// This means we need to guess based off the list of interfaces, which is
	// kind of crummy.  This will break horribly if the IGD device isn't on the
	// same network as the client, but that should be unlikely.
	remoteAddr, err := net.ResolveUDPAddr("udp4", c.ctrl.url.Host)
	if err != nil {
		return nil, err
	}
	addrList, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrList {
		if net, ok := addr.(*net.IPNet); ok {
			if net.IP.IsLoopback() {
				continue
			}
			if net.Contains(remoteAddr.IP) {
				return &net.IP, nil
			}
		}
	}

	// XXX: Maybe just return the first non-loopback interface we find as a
	// guess?  It's not like multi-homing is a thing right? *cries*
	return nil, fmt.Errorf("upnp: failed to determine local IP address")
}
