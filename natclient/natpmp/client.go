/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

// Package natpmp implements a NAT-PMP (RFC 6886) client suitable for NAT
// traversal.
package natpmp

import (
	"flag"
	"fmt"
	"net"
	"syscall"

	"github.com/yawning/go-fw-helper/natclient/base"
)

const (
	methodName = "NAT-PMP"

	natpmpPort   = 5351
	outgoingPort = 0
)

var allowDeletePortMapping = false

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
	tmp := c.conn.LocalAddr().(*net.UDPAddr)
	c.internalAddr = tmp.IP
	c.Vlogf("local IP is %s\n", c.internalAddr)

	// Fetch the external address as a test of the router.
	c.extAddr, err = c.GetExternalIPAddress()
	if err != nil {
		c.conn.Close()
		return nil, err
	}
	return c, nil
}

// Client is a NAT-PMP client instance.
type Client struct {
	verbose      bool
	conn         *net.UDPConn
	internalAddr net.IP
	gwAddr       net.IP
	extAddr      net.IP
}

// AddPortMapping adds a new TCP/IP port mapping.  The internal IP address of
// the client is used as the destination.  A 0 duration will request a 7200
// second lease.
func (c *Client) AddPortMapping(description string, internalPort, externalPort, duration int) error {
	if duration == 0 {
		duration = defaultMappingDuration
	}

	c.Vlogf("AddPortMapping: %s:%d <-> 0.0.0.0:%d (%d sec)\n", c.internalAddr, internalPort, externalPort, duration)

	req, err := newRequestMappingReq(internalPort, externalPort, duration)
	if err != nil {
		return err
	}
	r, err := c.issueRequest(req)
	if err != nil {
		c.Vlogf("failed to create Request Mapping request: %s", err)
		return err
	}
	if resp, ok := r.(*requestMappingResp); ok {
		// Check that resp.mappedPort = externalPort.
		if int(resp.mappedPort) == externalPort {
			return nil
		}

		// There was a conflict, and the router picked a different port than
		// requested.  Undo the mapping that isn't exactly what we wanted.
		c.DeletePortMapping(int(resp.internalPort), int(resp.mappedPort))

		c.Vlogf("router mapped a different external port than requested: %d\n", resp.mappedPort)
		return fmt.Errorf("router mapped a different external port than requested")
	}
	return fmt.Errorf("invalid response received to AddPortMapping")
}

// DeletePortMapping removes an existing TCP/IP port forwarding entry
// between clientIP:internalPort and 0.0.0.0:externalPort.
func (c *Client) DeletePortMapping(internalPort, externalPort int) error {
	// Old versions (non-master as of this writing) of miniupnpd don't handle
	// this correctly according to the spec (draft or RFC), so allowing this
	// will potentially blow away the incorrect mappings.
	if allowDeletePortMapping {
		req, err := newRequestMappingReq(internalPort, 0, 0)
		if err != nil {
			return err
		}
		_, err = c.issueRequest(req)
		return err
	}

	return syscall.ENOTSUP
}

// GetExternalIPAddress queries the router's external IP address.
func (c *Client) GetExternalIPAddress() (net.IP, error) {
	// This is cached during startup since it doubles as the "does the router
	// actually support this?" check.
	if c.extAddr != nil {
		c.Vlogf("using cached external address: %s\n", c.extAddr)
		return c.extAddr, nil
	}

	// First time we're querying the external IP, must be when we try to probe
	// for the presence of a device.
	c.Vlogf("querying external address\n")

	req := newExternalAddressReq()
	r, err := c.issueRequest(req)
	if err != nil {
		c.Vlogf("failed to query external address: %s\n", err)
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

// GetListOfPortMappings queries the router for the list of port forwarding
// entries.
func (c *Client) GetListOfPortMappings() ([]string, error) {
	return nil, syscall.ENOTSUP
}

func (c *Client) Close() {
	c.conn.Close()
}

func init() {
	// Undocumented flag that allows people to do something that's broken on
	// certain NAT-PMP stacks.
	flag.BoolVar(&allowDeletePortMapping, "natpmp-allow-delete", false, "")
}

var _ base.ClientFactory = (*ClientFactory)(nil)
var _ base.Client = (*Client)(nil)
