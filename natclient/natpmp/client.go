/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

// Package natpmp implements a NAT-PMP (RFC 6886) client suitable for NAT
// traversal.
package natpmp

import (
	"fmt"
	"net"

	"github.com/yawning/go-fw-helper/natclient/base"
)

const (
	methodName = "NAT-PMP"

	natpmpPort   = 5351
	outgoingPort = 0
)

type ClientFactory struct{}

func (f *ClientFactory) Name() string {
	return methodName
}

func (f *ClientFactory) New(verbose bool) (base.Client, error) {
	var err error

	c := &Client{verbose: verbose}
	c.gwAddr, err = getGateway()
	if err != nil {
		return nil, err
	}
	c.Vlogf("gwAddr is %s\n", c.gwAddr)

	// Initialize the UDP socket here.
	addr := &net.UDPAddr{IP: c.gwAddr, Port: natpmpPort}
	c.conn, err = net.DialUDP("udp4", nil, addr)
	if err != nil {
		c.Vlogf("failed to connect to router: %s\n", err)
		return nil, err
	}

	// Fetch the external address as a test of the router.
	c.extAddr, err = c.GetExternalIPAddress()
	if err != nil {
		c.conn.Close()
		return nil, err
	}
	return c, nil
}

type Client struct {
	verbose bool
	conn    *net.UDPConn
	gwAddr  net.IP
	extAddr net.IP
}

func (c *Client) AddPortMapping(description string, internalPort, externalPort, duration int) error {
	if duration == 0 {
		duration = defaultMappingDuration
	}

	req, err := newRequestMappingReq(internalPort, externalPort, duration)
	if err != nil {
		return err
	}
	r, err := c.issueRequest(req)
	if err != nil {
		return err
	}
	if resp, ok := r.(*requestMappingResp); ok {
		// Check that resp.mappedPort = externalPort.
		if int(resp.mappedPort) == externalPort {
			return nil
		}

		// There was a conflict, and the router picked a different port than
		// requested.  If this was a just world, where people could implement
		// simple specs, then we would uncomment the code block and
		// destroy the mapping that the router created.
		//
		// req, err := newRequestMappingReq(internalPort, 0, 0)
		// if err == nil {
		//  c.issueRequest(req)
		// }
		//
		// However the world is a harsh and cruel place and the miniupnpd
		// instance on my test router crashes when we try to delete mappings.
		return fmt.Errorf("router mapped a different external port than requested")
	}
	return fmt.Errorf("invalid response received to AddPortMapping")
}

func (c *Client) GetExternalIPAddress() (net.IP, error) {
	// This is cached during startup since it doubles as the "does the router
	// actually support this?" check.
	if c.extAddr != nil {
		return c.extAddr, nil
	}

	// Well ok, guess we need to hit the router up for this after all.
	req, err := newExternalAddressReq()
	if err != nil {
		return nil, err
	}
	r, err := c.issueRequest(req)
	if err != nil {
		return nil, err
	}
	if resp, ok := r.(*externalAddressResp); ok {
		c.extAddr = resp.extAddr
		return resp.extAddr, nil
	}
	return nil, fmt.Errorf("invalid response received to GetExternalIPAddress")
}

func (c *Client) Vlogf(f string, a ...interface{}) {
	if c.verbose {
		base.Vlogf(methodName+": "+f, a...)
	}
}

func (c *Client) Close() {
	c.conn.Close()
}

var _ base.ClientFactory = (*ClientFactory)(nil)
var _ base.Client = (*Client)(nil)
