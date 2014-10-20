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
	"net"
	"net/http"
	"strconv"
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
	Fault                        *soapFault        `xml:"Fault"`
	GetExternalIPAddressResponse *getExtIPResponse `xml:"GetExternalIPAddressResponse"`
}

type soapFault struct {
	FaultCode   string `xml:"faultcode"`
	FaultString string `xml:"faultstring"`
	Detail      string `xml:"detail"`
}

type getExtIPResponse struct {
	IP string `xml:"NewExternalIPAddress"`
}

func (f *soapFault) String() string {
	return fmt.Sprintf("fault: %s - %s", f.FaultCode, f.FaultString)
}

func (c *Client) issueSoapRequest(actionName, argsXML string) (*soapBody, error) {
	// Apparently a lot of routers puke horribly on XML that's well-formed but
	// not exactly what they expect, so requests are crafted by hand.  At a
	// future time when more than 2 requests need to be supported, revisit.
	const header = xml.Header +
		"<s:Envelope xmlns:=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
		"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" +
		"<s:Body>"
	const footer = "</s:Body></s:Envelope>"

	actionOpen := "<u:" + actionName + " xmlns:u=\"" + c.ctrl.urn.String() + "\">"
	actionClose := "</u:" + actionName + ">"
	body := []byte(header + actionOpen + argsXML + actionClose + footer)
	soapAction := "\"" + c.ctrl.urn.String() + "#" + actionName + "\""

	c.Vlogf("soap: issuing %s\n", actionName)

	reqBuf := bytes.NewBuffer(body)
	req, err := http.NewRequest("POST", c.ctrl.url.String(), bufio.NewReader(reqBuf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Soapaction", soapAction)

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
func (c *Client) GetExternalIPAddress() (*net.IP, error) {

	respBody, err := c.issueSoapRequest("GetExternalIPAddress", "")
	if err != nil {
		return nil, err
	}

	if respBody.GetExternalIPAddressResponse != nil {
		ip := net.ParseIP(respBody.GetExternalIPAddressResponse.IP)
		if ip != nil {
			return &ip, nil
		}
	}
	return nil, fmt.Errorf("igd: GetExternalIPAddress() failed")
}

// AddPortMapping adds a new TCP/IP port mapping.  The internal IP address of
// the client is used as the destination.  Per the UPnP spec, duration can
// range from 0 to 604800, with the behavior on 0 changing depending on the
// version of the spec.  This implementation treats 0 as "maximum duration",
// and not "permanent".
func (c *Client) AddPortMapping(descr string, internal, external, duration int) error {
	if duration == 0 {
		// UPnP 1.0 treats 0 as "permanent", but UPnP 1.1 does not allow the
		// creation of permanent mappings.  Normalize around UPnP 1.1 behavior.
		duration = maxMappingDuration
	}

	c.Vlogf("AddPortMapping: '%s' %s:%d <-> 0.0.0.0:%d (%d sec)\n", descr, c.internalAddr, internal, external, duration)

	argsXML := "<NewRemoteHost></NewRemoteHost>" +
		"<NewExternalPort>" + strconv.FormatUint(uint64(external), 10) + "</NewExternalPort>" +
		"<NewProtocol>TCP</NewProtocol>" +
		"<NewInternalPort>" + strconv.FormatUint(uint64(internal), 10) + "</NewInternalPort>" +
		"<NewInternalClient>" + c.internalAddr.String() + "</NewInternalClient>" +
		"<NewEnabled>1</NewEnabled>" +
		"<NewPortMappingDescription>" + descr + "</NewPortMappingDescription>" +
		"<NewLeaseDuration>" + strconv.FormatUint(uint64(duration), 10) + "</NewLeaseDuration>"

	// HTTP 200 means that things worked.  The response isn't interesting
	// enough to warrant parsing.
	_, err := c.issueSoapRequest("AddPortMapping", argsXML)
	if err != nil {
		return err
	}
	return nil
}
