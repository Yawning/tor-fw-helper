/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

// Package upnp implements a simple UPnP client suitable for NAT traversal.
package upnp

import (
	"net"

	"github.com/yawning/go-fw-helper/natclient/base"
)

const (
	methodName = "UPnP"

//	userAgent = "BeOS/5.0 UPnP/1.1 Helper/1.0"
	userAgent    = "" // Standardized, but optional.
	outgoingPort = 0
)

type ClientFactory struct{}

func (f *ClientFactory) Name() string {
	return methodName
}

func (f *ClientFactory) New(verbose bool) (base.Client, error) {
	var err error

	c := &Client{verbose: verbose}
	c.ctrl, c.internalAddr, err = c.discover()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Client is UPnP client instance.
type Client struct {
	verbose      bool
	ctrl         *controlPoint
	internalAddr net.IP
}

func (c *Client) Vlogf(f string, a ...interface{}) {
	if c.verbose {
		base.Vlogf(methodName+": "+f, a...)
	}
}

func (c *Client) Close() {
	// No state to clean up.
}

var _ base.ClientFactory = (*ClientFactory)(nil)
var _ base.Client = (*Client)(nil)
