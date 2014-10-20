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

func (f *ClientFactory) New() (base.Client, error) {
	var err error

	c := &Client{}
	c.ctrl, c.internalAddr, err = c.discover()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// Client is UPnP client instance.
type Client struct {
	ctrl         *controlPoint
	internalAddr net.IP
}

var _ base.ClientFactory = (*ClientFactory)(nil)
var _ base.Client = (*Client)(nil)
