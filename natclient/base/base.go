/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

// Package base defines the common interface for the various NAT port
// forwarding configuration methods.
package base

import (
	"fmt"
	"net"
	"os"
)

const (
	// VlogPrefix is the verbose logging output prefix.
	VlogPrefix = "V: "
)

// ClientFactory is a Client factory.
type ClientFactory interface {
	// Name returns the name of the port forwarding configuration mechanism.
	Name() string

	// Initializes and probes for a suitable configuration mechanism and
	// returns a ready to use Client.
	New(verbose bool) (Client, error)
}

// Client is a NAT port forwarding mechanism configuration client.
type Client interface {
	// AddPortMapping adds a new TCP/IP port forwarding entry between
	// clientIP:internalPort and 0.0.0.0:externalPort.  A duration of "0" will
	// have the backend pick an "appropriate" and "safe" duration.
	AddPortMapping(description string, internalPort, externalPort, duration int) error

	// GetExternalIPAddress queries the router for the external public IP
	// address.
	GetExternalIPAddress() (net.IP, error)

	// GetListOfPortMappings queries the router for the list of port forwarding
	// entries.
	GetListOfPortMappings() ([]string, error)

	// Vlogf logs verbose debugging messages to stderror.  It is up to the
	// implementation to squelch output when constructed with verbose = false.
	Vlogf(f string, a ...interface{})

	// Close cleans up all the state associated with the particular Client.
	Close()
}

// Vlogf logs verbose debugging messages to stderror.
func Vlogf(f string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, VlogPrefix+f, a...)
}
