/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

package upnp

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"git.torproject.org/tor-fw-helper.git/natclient/upnp/httpu"
)

const (
	mSearchMethod = "M-SEARCH"
	mSearchURL    = "*"
	mSearchHost   = "239.255.255.250:1900"
	mSearchMan    = "\"ssdp:discover\""
	mSearchMx     = "2"
	mSearchStRoot = "upnp:rootdevice"

	internetGatewayDevice = "InternetGatewayDevice"
	wanDevice             = "WANDevice"
	wanConnectionDevice   = "WANConnectionDevice"
	wanIPConnection       = "WANIPConnection"
	wanPPPConnection      = "WANPPPConnection"

	maxRetries     = 3
	requestTimeout = 2 * time.Second // Match mSearchMx
)

type controlPoint struct {
	url *url.URL
	urn *upnpURN
}

type upnpURN struct {
	domainName string
	kind       string
	kindType   string
	version    int
}

func (u *upnpURN) String() string {
	return fmt.Sprintf("urn:%s:%s:%s:%d", u.domainName, u.kind, u.kindType, u.version)
}

func parseURN(s string) (*upnpURN, error) {
	split := strings.Split(s, ":")
	if len(split) != 5 {
		return nil, fmt.Errorf("urn: malformed %d elements", len(split))
	}
	if split[0] != "urn" {
		return nil, fmt.Errorf("urn: invalid prefix")
	}
	v, err := strconv.ParseInt(split[4], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("urn: malformed version: %s", err)
	}
	return &upnpURN{split[1], split[2], split[3], int(v)}, nil
}

type upnpRoot struct {
	SpecVersion struct {
		Major int `xml:"major"`
		Minor int `xml:"minor"`
	} `xml:"specVersion"`
	URLBase string     `xml:"URLBase"`
	Device  upnpDevice `xml:"device"`
}

type upnpDevice struct {
	DeviceType   string          `xml:"deviceType"`
	FriendlyName string          `xml:"friendlyName"`
	Manufacturer string          `xml:"manufacturer"`
	ModelName    string          `xml:"modelName"`
	UDN          string          `xml:"UDN"`
	DeviceList   upnpDeviceList  `xml:"deviceList"`
	ServiceList  upnpServiceList `xml:"serviceList"`
}

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ServiceID   string `xml:"serviceId"`
	SCPDURL     string `xml:"SCPDURL"`
	ControlURL  string `xml:"controlURL"`
	EventSubURL string `xml:"eventSubURL"`
}

type upnpDeviceList struct {
	Device []upnpDevice `xml:"device"`
}

type upnpServiceList struct {
	Service []upnpService `xml:"service"`
}

func (d *upnpDevice) is(k string) bool {
	urn, err := parseURN(d.DeviceType)
	if err != nil {
		return false
	}
	return urn.kind == "device" && urn.kindType == k
}

func (s *upnpService) is(k string) bool {
	urn, err := parseURN(s.ServiceType)
	if err != nil {
		return false
	}
	return urn.kind == "service" && urn.kindType == k
}

func (d *upnpDevice) findChild(k string) *upnpDevice {
	for _, dd := range d.DeviceList.Device {
		if dd.is(k) {
			return &dd
		}
	}
	return nil
}

func (d *upnpDevice) findService(k string) *upnpService {
	for _, s := range d.ServiceList.Service {
		if s.is(k) {
			return &s
		}
	}
	return nil
}

func (c *Client) discover() (cp *controlPoint, localAddr net.IP, err error) {
	// The uPNP discovery process is 3 steps.
	//  1. Figure out where the relevant device is via M-SEARCH over UDP
	//     multicast.
	//  2. Pull down the "Device Description" XML document to figure out the
	//     controlURL and SCPDURL for the desired services.
	//  3. Pull down the "Service Description" document for each of the
	//     services, to figure out the details.
	//
	// This implementation skips step 3 because all of the desired services are
	// so basic that only the most shady fly-by-night of uPNP implementors will
	// screw them up to the point where our calls don't "work" (Note: At least
	// historically, most shady fly-by-night uPNP implementors like Broadcom
	// have screwed up UPnP to the point where "work" is loosely defined.)

	// 1. Find the target devices.
	c.Vlogf("probing for UPNP root devices via M-SEARCH\n")
	rootXMLLocs, err := discoverRootDevices()
	if err != nil {
		return nil, nil, err
	}

	c.Vlogf("received %d potential root devices\n", len(rootXMLLocs))

	for _, rootLoc := range rootXMLLocs {
		// 2. Pull down the "Device Description" document.
		c.Vlogf("downloading 'Device Description' from %s\n", rootLoc)
		rootXML, localAddr, err := retrieveDeviceDescription(rootLoc)
		if err != nil {
			c.Vlogf("download failed: %s\n", err)
			continue
		}

		// Figure out the controlURL (and SCPDURL).
		//
		//  -+- InternetGatewayDevice
		//       |
		//       +- WANDevice
		//       |   |
		//       |   +- WANConnectionDevice
		//       |   |   |
		//       |   |   +- WANIPConnection (Service)
		//       |   |   |
		//       |   |   +- WANPPPConnection (Service)
		//
		// Ugh.  Technically things under the InternetGatewayDevice can be
		// duplicated, but if anyone has a multihomed home router with more
		// than one uplink connection, it's probably ok to assume that they
		// can setup port forwarding themselves, or can pay someone to do so.
		cp = &controlPoint{}
		var urlBase *url.URL
		if rootXML.SpecVersion.Major == 1 && rootXML.SpecVersion.Minor == 0 {
			// uPNP 1.0 has an optional URLBase that is used as the base for
			// all of the relative URLs.  uPNP 1.1 and later do the sensible
			// thing and just use absolute URLs everywhere.
			if rootXML.URLBase != "" {
				urlBase, err = url.Parse(rootXML.URLBase)
				if err != nil {
					c.Vlogf("malformed URLBase: %s\n", err)
					continue
				}
			} else {
				// Per the spec: "If URLBase is empty or not given, the base
				// URL is the URL from which the device description was
				// retreived.
				urlBase = &url.URL{Scheme: rootLoc.Scheme, Host: rootLoc.Host}
			}
		}
		rootD := rootXML.Device // InternetGatewayDevice
		c.Vlogf("device: %s - %s\n", rootD.Manufacturer, rootD.ModelName)
		if !rootD.is(internetGatewayDevice) {
			c.Vlogf("root device is not a %s\n", internetGatewayDevice)
			continue
		}
		wanD := rootD.findChild(wanDevice) // WANDevice
		if wanD == nil {
			c.Vlogf("device does not have a %s\n", wanDevice)
			continue
		}
		wanConnD := wanD.findChild(wanConnectionDevice) // WANConnectionDevice
		if wanConnD == nil {
			c.Vlogf("device does not have a %s\n", wanConnectionDevice)
			continue
		}

		// WANIPConnection is the prefered service to use, though a lot of
		// routers export both, and really old DSL modems only export one.
		// Check both, with preference towards the new hotness, what we want to
		// do works with either.
		okServices := []string{wanIPConnection, wanPPPConnection}
		for _, svc := range okServices {
			s := wanConnD.findService(svc)
			if s != nil {
				if urlBase != nil {
					// ControlURL is relative, so build it using urlBase.
					// This assumes that none of the routers use a BaseURL or
					// ControlURL that contains querys or fragments, which may
					// be incorrect.
					cp.url = urlBase
					cp.url.Path = path.Join(cp.url.Path, s.ControlURL)
				} else {
					// ControlURL is absolute.
					cp.url, err = url.Parse(s.ControlURL)
					if err != nil {
						c.Vlogf("malformed ControlURL: %s\n", err)
						continue
					}
				}
				cp.urn, _ = parseURN(s.ServiceType)

				// 3. Pull down the "Service Description" document. (Skipped)
				c.Vlogf("found a %s at %s\n", cp.urn.kindType, cp.url)
				c.Vlogf("local IP is %s\n", localAddr)

				return cp, localAddr, nil
			}
		}

		c.Vlogf("device has no compatible upstream services\n")
	}
	return nil, nil, fmt.Errorf("failed to find a compatible service")
}

func discoverRootDevices() ([]*url.URL, error) {
	// 1.3.2 Search request with M-SEARCH
	//
	// This is done via a HTTPMU request.  The response is unicasted back.
	//
	// The request is formatted as thus:
	//  M-SEARCH * HTTP/1.1
	//  HOST: 239.255.255.250:1900
	//  MAN: "ssdp:discover"
	//  MX: seconds to delay response
	//  ST: search target
	//  USER-AGENT: OS/version UPnP/1.1 product/version
	req, err := http.NewRequest(mSearchMethod, "", nil)
	if err != nil {
		return nil, err
	}
	req.Host = mSearchHost
	req.URL.Opaque = mSearchURL // NewRequest escapes the path, use Opaque.
	req.Header.Set("MAN", mSearchMan)
	req.Header.Set("MX", mSearchMx)
	req.Header.Set("ST", mSearchStRoot)
	req.Header.Set("User-Agent", userAgent)

	hc, err := httpu.New(outgoingPort)
	if err != nil {
		return nil, err
	}
	resps, err := hc.Do(req, requestTimeout, maxRetries)
	if err != nil {
		return nil, err
	}
	locs := make([]*url.URL, 0, len(resps))
	for _, resp := range resps {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		if resp.Header.Get("ST") != req.Header.Get("ST") {
			continue
		}
		xmlLoc, err := url.Parse(resp.Header.Get("Location"))
		if err != nil {
			continue
		}
		locs = append(locs, xmlLoc)
	}
	if len(locs) > 0 {
		return locs, nil
	}
	return nil, fmt.Errorf("ssdp: failed to discover any root devices")
}

func retrieveDeviceDescription(xmlLoc *url.URL) (*upnpRoot, net.IP, error) {
	c, err := net.Dial("tcp", xmlLoc.Host)
	if err != nil {
		return nil, nil, err
	}
	conn := httputil.NewClientConn(c, nil)
	defer conn.Close()

	// At this point we have the local address of the http socket, that can
	// apparently talk to the UPnP device, so save that off as the local
	// address.
	localAddr := c.LocalAddr()

	req, err := http.NewRequest("GET", xmlLoc.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := conn.Do(req)
	if err != nil && err != httputil.ErrPersistEOF {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("XML fetch failed with status: %s", resp.Status)
	}
	xmlDoc, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	rewt := &upnpRoot{}
	if err = xml.Unmarshal(xmlDoc, rewt); err != nil {
		return nil, nil, err
	}

	// This should always be true, but be paranoid.
	if tcpAddr, ok := localAddr.(*net.TCPAddr); ok {
		return rewt, tcpAddr.IP, nil
	}

	return nil, nil, fmt.Errorf("failed to determine local address")
}
