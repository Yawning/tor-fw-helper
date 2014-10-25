/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

package upnp

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"strconv"
	"syscall"
)

const maxMappingDuration = 604800

// The people who made this abomination of a protocol used SOAP.  Presumably
// the "right" way to do this is to use an existing SOAP client, but Go does
// not have such a thing.

type soapEnvelope struct {
	XMLName       xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	EncodingStyle string   `xml:"http://schemas.xmlsoap.org/soap/envelope/ encodingStyle,attr"`
	Body          soapBody `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
}

type soapBody struct {
	Fault                              *soapFault             `xml:"Fault"`
	GetExternalIPAddressResponse       *getExtIPResponse      `xml:"GetExternalIPAddressResponse"`
	GetGenericPortMappingEntryResponse *getGenPMapEntResponse `xml:"GetGenericPortMappingEntryResponse"`
}

type soapFault struct {
	FaultCode   string      `xml:"faultcode"`
	FaultString string      `xml:"faultstring"`
	Detail      *soapDetail `xml:"detail"`
}

type soapDetail struct {
	UPnPError *upnpError `xml:"UPnPError"`
}

type upnpError struct {
	ErrorCode        int    `xml:"errorCode"`
	ErrorDescription string `xml:"errorDescription"`
}

type getExtIPResponse struct {
	IP string `xml:"NewExternalIPAddress"`
}

type getGenPMapEntResponse struct {
	RemoteHost             string `xml:"NewRemoteHost"`
	ExternalPort           int    `xml:"NewExternalPort"`
	Protocol               string `xml:"NewProtocol"`
	InternalPort           int    `xml:"NewInternalPort"`
	InternalClient         string `xml:"NewInternalClient"`
	Enabled                int    `xml:"NewEnabled"`
	PortMappingDescription string `xml:"NewPortMappingDescription"`
	LeaseDuration          int    `xml:"NewLeaseDuration"`
}

func (f *soapFault) String() string {
	if f.Detail.UPnPError != nil {
		return fmt.Sprintf("upnp error: %d - %s", f.Detail.UPnPError.ErrorCode, f.Detail.UPnPError.ErrorDescription)
	}
	return fmt.Sprintf("fault: %s - %s", f.FaultCode, f.FaultString)
}

func (c *Client) issueSoapRequest(actionName, argsXML string) (*soapBody, error) {
	// Apparently a lot of routers puke horribly on XML that's well-formed but
	// not exactly what they expect, so requests are crafted by hand.  At a
	// future time when more than 2 requests need to be supported, revisit.
	const header = xml.Header +
		"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
		"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
		"<s:Body>"
	const footer = "</s:Body></s:Envelope>"

	actionOpen := "<u:" + actionName + " xmlns:u=\"" + c.ctrl.urn.String() + "\">"
	actionClose := "</u:" + actionName + ">"
	body := []byte(header + actionOpen + argsXML + actionClose + footer)
	soapAction := "\"" + c.ctrl.urn.String() + "#" + actionName + "\""

	c.Vlogf("soap: issuing %s\n", actionName)

	// miniupnpd (used by a lot of routers) can't handle chunked transfer
	// encoding at all and just passes the raw body to it's XML parser.  This
	// is all sorts of garbage and violates RFC 2616.
	reqBuf := bytes.NewBuffer(body)
	req, err := http.NewRequest("POST", c.ctrl.url.String(), bufio.NewReader(reqBuf))
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(body))
	req.TransferEncoding = []string{"identity"}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("SOAPAction", soapAction)

	httpTransport := &http.Transport{DisableKeepAlives: true, DisableCompression: true}
	httpClient := &http.Client{Transport: httpTransport}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	respEnvelope := &soapEnvelope{}
	if err = xml.Unmarshal(body, respEnvelope); err != nil {
		return nil, err
	}
	if respEnvelope.Body.Fault != nil {
		return nil, fmt.Errorf("soap: %s", respEnvelope.Body.Fault)
	}
	if resp.StatusCode != http.StatusOK {
		// Yes, this is at the end because the SOAP Fault gives more useful
		// diagnostics than "500 Internal Server Error".
		return nil, fmt.Errorf("soap: request failed with status: %s", resp.Status)
	}
	return &respEnvelope.Body, nil
}

// GetExternalIPAddress queries the router's external IP address.
func (c *Client) GetExternalIPAddress() (net.IP, error) {

	respBody, err := c.issueSoapRequest("GetExternalIPAddress", "")
	if err != nil {
		return nil, err
	}

	if respBody.GetExternalIPAddressResponse != nil {
		ip := net.ParseIP(respBody.GetExternalIPAddressResponse.IP)
		if ip != nil {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("igd: GetExternalIPAddress() failed")
}

// GetListOfPortMappings queries the router for the list of port forwarding
// entries.
func (c *Client) GetListOfPortMappings() ([]string, error) {
	// Sad panda, GetListOfPortMappings requires IDG2 or later, so emulate it
	// with GetGenericPortMappingEntry.  Theoretically if the number of entries
	// changes during this process we would need to start over from the
	// begining, but we don't monitor events so we can't tell.

	resps := make([]string, 0)
	for idx := 0; idx < math.MaxUint16; idx++ {
		argsXML := "<NewPortMappingIndex>" + strconv.FormatUint(uint64(idx), 10) + "</NewPortMappingIndex>"
		respBody, err := c.issueSoapRequest("GetGenericPortMappingEntry", argsXML)
		if err != nil {
			// Probably SpecifiedArrayIndexInvalid. (XXX: Check?)
			c.Vlogf("igd: GetGenericPortMappingEntry returned: %s\n", err)
			break
		}
		if respBody.GetGenericPortMappingEntryResponse != nil {
			// Too long, much too long.
			r := respBody.GetGenericPortMappingEntryResponse
			remoteHost := r.RemoteHost
			if remoteHost == "" {
				remoteHost = "0.0.0.0"
			}
			s := fmt.Sprintf("'%s' %s:%d <-> %s:%d %s (%d sec)",
				r.PortMappingDescription,
				r.InternalClient,
				r.InternalPort,
				remoteHost,
				r.ExternalPort,
				r.Protocol,
				r.LeaseDuration)
			c.Vlogf("%s\n", s)
			resps = append(resps, s)
		}
	}
	return resps, nil
}

// AddPortMapping adds a new TCP/IP port mapping.  The internal IP address of
// the client is used as the destination.  Per the UPnP spec, duration can
// range from 0 to 604800, with the behavior on 0 changing depending on the
// version of the spec.
func (c *Client) AddPortMapping(descr string, internalPort, externalPort, duration int) error {
	if duration > maxMappingDuration {
		return syscall.ERANGE
	}

	c.Vlogf("AddPortMapping: '%s' %s:%d <-> 0.0.0.0:%d (%d sec)\n", descr, c.internalAddr, internalPort, externalPort, duration)

	argsXML := "<NewRemoteHost></NewRemoteHost>" +
		"<NewExternalPort>" + strconv.FormatUint(uint64(externalPort), 10) + "</NewExternalPort>" +
		"<NewProtocol>TCP</NewProtocol>" +
		"<NewInternalPort>" + strconv.FormatUint(uint64(internalPort), 10) + "</NewInternalPort>" +
		"<NewInternalClient>" + c.internalAddr.String() + "</NewInternalClient>" +
		"<NewEnabled>1</NewEnabled>" +
		"<NewPortMappingDescription>" + descr + "</NewPortMappingDescription>" +
		"<NewLeaseDuration>" + strconv.FormatUint(uint64(duration), 10) + "</NewLeaseDuration>"

	// HTTP 200 means that things worked.  The response isn't interesting
	// enough to warrant parsing.
	_, err := c.issueSoapRequest("AddPortMapping", argsXML)
	if err != nil {
		c.Vlogf("igd: AddPortMapping failed: %s\n", err)
		return err
	}
	return nil
}

// DeletePortMapping removes an existing TCP/IP port forwarding entry
// between clientIP:internalPort and 0.0.0.0:externalPort.
func (c *Client) DeletePortMapping(internalPort, externalPort int) error {
	c.Vlogf("DeletePortMapping: %s:%d <-> 0.0.0.0:%d\n", c.internalAddr, internalPort, externalPort)

	argsXML := "<NewRemoteHost></NewRemoteHost>" +
		"<NewExternalPort>" + strconv.FormatUint(uint64(externalPort), 10) + "</NewExternalPort>" +
		"<NewProtocol>TCP</NewProtocol>"

	// HTTP 200 means that things worked.  The response isn't interesting
	// enough to warrant parsing.
	_, err := c.issueSoapRequest("DeletePortMapping", argsXML)
	if err != nil {
		c.Vlogf("igd: DeletePortMapping failed: %s\n", err)
		return err
	}
	return nil
}
