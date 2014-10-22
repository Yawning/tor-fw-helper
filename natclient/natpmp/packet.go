/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

package natpmp

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"syscall"
	"time"
)

const (
	version = 0

	opExternalAddress   = 0
	opRequestMappingUDP = 1
	opRequestMappingTCP = 2
	opRespOffset        = 128

	respSuccess            = 0
	respUnsupportedVersion = 1
	respNotAuthorized      = 2
	respNetworkFailure     = 3
	respOutOfResources     = 4
	respUnsupportedOpcode  = 5

	maxLength                 = 1100 // From RFC 6887
	hdrLength                 = 2
	externalAddressRespLength = 12
	requestMappingReqLength   = 12
	requestMappingRespLength  = 16

	defaultMappingDuration = 7200
	initialTimeoutDuration = 250 * time.Millisecond
	maxRetries             = 3
)

type packetHdr struct {
	version uint8
	op      uint8
}

type externalAddressResp struct {
	packetHdr
	resultCode uint16
	epochTime  uint32
	extAddr    net.IP
}

type requestMappingResp struct {
	packetHdr
	resultCode      uint16
	epochTime       uint32
	internalPort    uint16
	mappedPort      uint16
	mappingLifetime uint32
}

func decodePacketHdr(raw []byte) (*packetHdr, error) {
	if len(raw) < hdrLength {
		return nil, fmt.Errorf("packet too short to contain header: %d", len(raw))
	}

	return &packetHdr{version: raw[0], op: raw[1]}, nil
}

func newExternalAddressReq() ([]byte, error) {
	//   0                   1
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Vers = 0      | OP = 0        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	return []byte{version, opExternalAddress}, nil
}

func decodeExternalAddressResp(raw []byte) (*externalAddressResp, error) {
	//   0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Vers = 0      | OP = 128 + 0  | Result Code (net byte order)  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Seconds Since Start of Epoch (in network byte order)          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | External IPv4 Address (a.b.c.d)                               |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	h, err := decodePacketHdr(raw)
	if err != nil {
		return nil, err
	}
	if h.op != opExternalAddress+opRespOffset {
		return nil, fmt.Errorf("not a External Address Response: %d", h.op)
	}
	if len(raw) != externalAddressRespLength {
		return nil, fmt.Errorf("invalid packet length: %d", len(raw))
	}

	p := &externalAddressResp{*h, 0, 0, nil}
	p.resultCode = binary.BigEndian.Uint16(raw[2:4])
	p.epochTime = binary.BigEndian.Uint32(raw[4:8])
	if p.resultCode == respSuccess {
		p.extAddr = net.IPv4(raw[8], raw[9], raw[10], raw[11])
	}
	return p, nil
}

func newRequestMappingReq(internal, external, duration int) ([]byte, error) {
	//   0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Vers = 0      | OP = x        | Reserved                      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Internal Port                 | Suggested External Port       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Requested Port Mapping Lifetime in Seconds                    |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// 0 is allowed for all of the values when doing removal.
	if internal < 0 || internal > math.MaxUint16 {
		return nil, syscall.ERANGE
	}
	if external < 0 || external > math.MaxUint32 {
		return nil, syscall.ERANGE
	}
	if duration < 0 || duration > math.MaxUint32 {
		return nil, syscall.ERANGE
	}

	req := make([]byte, requestMappingReqLength)
	req[0] = version
	req[1] = opRequestMappingTCP // TODO: Allow UDP later?
	binary.BigEndian.PutUint16(req[4:6], uint16(internal))
	binary.BigEndian.PutUint16(req[6:8], uint16(external))
	binary.BigEndian.PutUint32(req[8:12], uint32(duration))
	return req, nil
}

func decodeRequestMappingResp(raw []byte) (*requestMappingResp, error) {
	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Vers = 0      | OP = 128 + x  | Result Code                   |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Seconds Since Start of Epoch                                  |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Internal Port                 | Mapped External Port          |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Port Mapping Lifetime in Seconds                              |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	h, err := decodePacketHdr(raw)
	if err != nil {
		return nil, err
	}
	if h.op != opRequestMappingTCP+opRespOffset {
		return nil, fmt.Errorf("not a Request Mapping Response: %d", h.op)
	}
	if len(raw) != requestMappingRespLength {
		return nil, fmt.Errorf("invalid packet length: %d", len(raw))
	}

	p := &requestMappingResp{*h, 0, 0, 0, 0, 0}
	p.resultCode = binary.BigEndian.Uint16(raw[2:4])
	p.epochTime = binary.BigEndian.Uint32(raw[4:8])
	p.internalPort = binary.BigEndian.Uint16(raw[8:10])
	p.mappedPort = binary.BigEndian.Uint16(raw[10:12])
	p.mappingLifetime = binary.BigEndian.Uint32(raw[12:16])
	return p, nil
}

func resultCodeToError(code uint16) error {
	switch code {
	case respSuccess:
		return nil
	case respUnsupportedVersion:
		return fmt.Errorf("unsupported NAT-PMP version")
	case respNotAuthorized:
		return fmt.Errorf("not authorized/refused")
	case respNetworkFailure:
		return fmt.Errorf("network failure")
	case respOutOfResources:
		return fmt.Errorf("out of resources")
	case respUnsupportedOpcode:
		return fmt.Errorf("unsupported opcode")
	default:
		return fmt.Errorf("unknown failure")
	}
}

func (c *Client) issueRequest(req []byte) (interface{}, error) {
	defer c.conn.SetDeadline(time.Time{})

	timeoutAt := time.Now()
	rawRespBuf := make([]byte, maxLength)
	for i := 0; i < maxRetries; i++ {
		now := time.Now()
		if timeoutAt.After(now) {
			time.Sleep(timeoutAt.Sub(now))
		}
		timeoutAt = time.Now().Add(initialTimeoutDuration << uint(i))
		if err := c.conn.SetDeadline(timeoutAt); err != nil {
			return nil, err
		}

		if _, err := c.conn.Write(req); err != nil {
			if nerr, ok := err.(net.Error); ok {
				if nerr.Temporary() || nerr.Timeout() {
					continue
				}
			}
			return nil, err
		}

		for {
			n, err := c.conn.Read(rawRespBuf)
			if err != nil {
				break
			}
			// Ensure that the version/opcode exist.
			if n < hdrLength {
				continue
			}
			// Peek at the opcode to see if it corresponds to the request.
			if rawRespBuf[1] != req[1]+opRespOffset {
				continue
			}
			// Decode as appropriate.
			switch rawRespBuf[1] {
			case opExternalAddress + opRespOffset:
				return decodeExternalAddressResp(rawRespBuf[:n])
			case opRequestMappingTCP + opRespOffset:
				return decodeRequestMappingResp(rawRespBuf[:n])
			default:
				// IDK WTF this is, oh well.
				return rawRespBuf[:n], nil
			}
		}
	}
	return nil, syscall.ETIMEDOUT
}
