/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

// Package base defines the common interface for the various NAT port
// forwarding configuration methods.
package base

import (
	"net"
)

// ClientFactory is a Client factory.
type ClientFactory interface {
	// Name returns the name of the port forwarding configuration mechanism.
	Name() string

	// Initializes and probes for a suitable configuration mechanism and
	// returns a ready to use Client.
	New() (Client, error)
}

// Client is a NAT port forwarding mechanism configuration client.
type Client interface {
	// AddPortMapping adds a new TCP/IP port forwarding entry between
	// clientIP:internalPort and 0.0.0.0:externalPort.
	AddPortMapping(description string, internalPort, externalPort, duration int) error

	// GetExternalIPAddress queries the router for the external public IP
	// address.
	GetExternalIPAddress() (*net.IP, error)
}
