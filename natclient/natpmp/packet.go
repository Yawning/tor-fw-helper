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

	resSuccess            = 0
	resUnsupportedVersion = 1
	resNotAuthorized      = 2
	resNetworkFailure     = 3
	resOutOfResources     = 4
	resUnsupportedOpcode  = 5

	maxLength                 = 1100 // From RFC 6887
	hdrLength                 = 4
	externalAddressRespLength = hdrLength + 8
	requestMappingReqLength   = hdrLength + 8
	requestMappingRespLength  = hdrLength + 12

	defaultMappingDuration = 7200
	initialTimeoutDuration = 250 * time.Millisecond
	maxRetries             = 3 // Spec says 9, but too long
)

type packetHdr struct {
	version    uint8
	op         uint8
	resultCode uint16
}

type packetReq interface {
	op() uint8
	encode() []byte
}

type externalAddressResp struct {
	packetHdr
	epochTime uint32
	extAddr   net.IP
}

type requestMappingResp struct {
	packetHdr
	epochTime       uint32
	internalPort    uint16
	mappedPort      uint16
	mappingLifetime uint32
}

type externalAddressReq struct{}

type requestMappingReq struct {
	internalPort    uint16
	externalPort    uint16
	mappingLifetime uint32
}

func decodePacketHdr(raw []byte) (*packetHdr, error) {
	if len(raw) < hdrLength {
		return nil, fmt.Errorf("packet too short to contain header: %d", len(raw))
	}
	h := &packetHdr{}
	h.version = raw[0]
	h.op = raw[1]
	h.resultCode = binary.BigEndian.Uint16(raw[2:4])

	return h, nil
}

func newExternalAddressReq() (*externalAddressReq, error) {
	return &externalAddressReq{}, nil
}

func (r *externalAddressReq) op() uint8 {
	return opExternalAddress
}

func (r *externalAddressReq) encode() []byte {
	//   0                   1
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Vers = 0      | OP = 0        |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	return []byte{version, r.op()}
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
	if h.resultCode != resSuccess {
		return nil, resultCodeToError(h.resultCode)
	}
	if len(raw) != externalAddressRespLength {
		return nil, fmt.Errorf("invalid packet length: %d", len(raw))
	}

	p := &externalAddressResp{*h, 0, nil}
	p.epochTime = binary.BigEndian.Uint32(raw[4:8])
	p.extAddr = net.IPv4(raw[8], raw[9], raw[10], raw[11])
	return p, nil
}

func newRequestMappingReq(internal, external, duration int) (*requestMappingReq, error) {
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

	return &requestMappingReq{internalPort: uint16(internal), externalPort: uint16(external), mappingLifetime: uint32(duration)}, nil
}

func (r *requestMappingReq) op() uint8 {
	return opRequestMappingTCP
}

func (r *requestMappingReq) encode() []byte {
	//   0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Vers = 0      | OP = x        | Reserved                      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Internal Port                 | Suggested External Port       |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Requested Port Mapping Lifetime in Seconds                    |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	raw := make([]byte, requestMappingReqLength)
	raw[0] = version
	raw[1] = r.op()
	binary.BigEndian.PutUint16(raw[4:6], r.internalPort)
	binary.BigEndian.PutUint16(raw[6:8], r.externalPort)
	binary.BigEndian.PutUint32(raw[8:12], r.mappingLifetime)
	return raw
}

func decodeRequestMappingResp(req *requestMappingReq, raw []byte) (*requestMappingResp, error) {
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
	if h.op != req.op()+opRespOffset {
		return nil, fmt.Errorf("not a Request Mapping Response: %d", h.op)
	}
	if h.resultCode != resSuccess {
		return nil, resultCodeToError(h.resultCode)
	}
	if len(raw) != requestMappingRespLength {
		return nil, fmt.Errorf("invalid packet length: %d", len(raw))
	}

	p := &requestMappingResp{*h, 0, 0, 0, 0}
	p.epochTime = binary.BigEndian.Uint32(raw[4:8])
	p.internalPort = binary.BigEndian.Uint16(raw[8:10])
	p.mappedPort = binary.BigEndian.Uint16(raw[10:12])
	p.mappingLifetime = binary.BigEndian.Uint32(raw[12:16])
	if req.internalPort != p.internalPort {
		return nil, fmt.Errorf("state Request Mapping Response : %d", p.internalPort)
	}
	return p, nil
}

func resultCodeToError(code uint16) error {
	switch code {
	case resSuccess:
		return nil
	case resUnsupportedVersion:
		return fmt.Errorf("unsupported NAT-PMP version")
	case resNotAuthorized:
		return fmt.Errorf("not authorized/refused")
	case resNetworkFailure:
		return fmt.Errorf("network failure")
	case resOutOfResources:
		return fmt.Errorf("out of resources")
	case resUnsupportedOpcode:
		return fmt.Errorf("unsupported opcode")
	default:
		return fmt.Errorf("unknown failure")
	}
}

func (c *Client) issueRequest(req packetReq) (interface{}, error) {
	defer c.conn.SetDeadline(time.Time{})

	rawReq := req.encode()
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

		if _, err := c.conn.Write(rawReq); err != nil {
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
			if rawRespBuf[1] != req.op()+opRespOffset {
				continue
			}
			// Decode as appropriate.
			switch rawRespBuf[1] {
			case opExternalAddress + opRespOffset:
				return decodeExternalAddressResp(rawRespBuf[:n])
			case opRequestMappingTCP + opRespOffset:
				// Be tolerant of errors when decoding this response type as
				// it is possible though extremely unlikely to get stale
				// responses.
				mReq := req.(*requestMappingReq)
				resp, err := decodeRequestMappingResp(mReq, rawRespBuf[:n])
				if err == nil {
					return resp, nil
				}
			default:
				// IDK WTF this is, oh well, surely when adding support for
				// other opcodes, people will add more case statements.
				return rawRespBuf[:n], nil
			}
		}
	}
	return nil, syscall.ETIMEDOUT
}

var _ packetReq = (*externalAddressReq)(nil)
var _ packetReq = (*requestMappingReq)(nil)
