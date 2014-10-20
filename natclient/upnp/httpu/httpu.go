/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

// Package httpu implements a HTTP(M)U client as specified in the IETF
// draft "Multicast and Unicast UDP HTTP Messages".
package httpu

import (
	"bufio"
	"bytes"
	"math"
	"net"
	"net/http"
	"syscall"
	"time"
)

const (
	maxResponseSize = math.MaxUint16
)

// Client is a HTTP(M)U client instance.
type Client struct {
	localAddr *net.UDPAddr
}

// New creates a new HTTP(M)U client instance that will bind to
// "0.0.0.0:localPort" when making outgoing requests.  Note that the UDP socket
// is re-initialized after each request to try to flush out the receive buffer.
func New(localPort int) (*Client, error) {
	if localPort > math.MaxUint16 {
		return nil, syscall.ERANGE
	}
	localAddr := &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: localPort}
	return &Client{localAddr: localAddr}, nil
}

// Do issues a HTTP(M)U request, and returns the response(s).  This method is
// not threadsafe.
func (c *Client) Do(r *http.Request, timeout time.Duration, retries int) ([]*http.Response, error) {
	addr, err := net.ResolveUDPAddr("udp4", r.Host)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", c.localAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if c.localAddr.Port == 0 {
		// If the local port is set to "any", query the port that was actually
		// used so that it can be preserved across invocations.
		tmp := conn.LocalAddr().(*net.UDPAddr)
		c.localAddr.Port = tmp.Port
	}

	reqBuf := bytes.NewBuffer(nil)
	if err := r.Write(reqBuf); err != nil {
		return nil, err
	}

	respList := make([]*http.Response, 0, 4)
	rawRespBuf := make([]byte, maxResponseSize)
	timeoutAt := time.Now()
	for i := 0; i < retries; i++ {
		// Ensure that the full timeout interval passes between requests to
		// avoid spamming the network.
		now := time.Now()
		if timeoutAt.After(now) {
			time.Sleep(timeoutAt.Sub(now))
		}
		timeoutAt = time.Now().Add(timeout)
		if err := conn.SetDeadline(timeoutAt); err != nil {
			return nil, err
		}

		// Issue the request.
		if _, err := conn.WriteTo(reqBuf.Bytes(), addr); err != nil {
			if nerr, ok := err.(net.Error); ok {
				if nerr.Temporary() || nerr.Timeout() {
					continue
				}
			}
			// Don't retry on non-transient network errors.
			return nil, err
		}

		// It's possible that multiple replies arrive (Eg: uPNP multicast
		// service discovery), so keep attempting to read reponses till the
		// timeout is reached.  Reponses not being valid HTTP responses is
		// possible (if unlikely) since anyone can send UDP, so parse errors
		// are ignored.
		for {
			n, _, err := conn.ReadFrom(rawRespBuf)
			if err != nil {
				break
			}

			respBuf := bytes.NewBuffer(rawRespBuf[:n])
			resp, err := http.ReadResponse(bufio.NewReader(respBuf), r)
			if err != nil {
				continue
			}
			respList = append(respList, resp)
		}

		// If there was at least one response, assume we got all the responses
		// and bail.
		if len(respList) > 0 {
			return respList, nil
		}
	}
	return nil, syscall.ETIMEDOUT
}
