/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

// Package natclient provides interfaces to various NAT port forwarding
// configuration methods.
package natclient

import (
	"fmt"

	"github.com/yawning/tor-fw-helper/natclient/base"
	"github.com/yawning/tor-fw-helper/natclient/natpmp"
	"github.com/yawning/tor-fw-helper/natclient/upnp"
)

var factories = make(map[string]base.ClientFactory)
var factoryNames []string

func registerFactory(f base.ClientFactory) {
	name := f.Name()
	e := factories[name]
	if e != nil {
		panic(fmt.Sprintf("factory '%s' is already registered", name))
	}
	factories[name] = f
	factoryNames = append(factoryNames, name)
}

// New attempts to initialize a port forwarding mechanism that is compatible
// with the local network.  If the protocol is not specified, the first
// compatible backend will be chosen.  Currently supported protocols are "UPnP"
// and "NAT-PMP".
func New(protocol string, verbose bool) (base.Client, error) {
	if protocol != "" {
		f := factories[protocol]
		if f == nil {
			return nil, fmt.Errorf("unknown protocol '%s'", protocol)
		}
		return invokeFactory(f, verbose)
	}
	for _, name := range factoryNames {
		f := factories[name]
		c, err := invokeFactory(f, verbose)
		if c != nil && err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("failed to initialize/discover a port forwarding mechanism")
}

func invokeFactory(f base.ClientFactory, verbose bool) (base.Client, error) {
	name := f.Name()
	if verbose {
		base.Vlogf("attempting backend: %s\n", name)
	}
	c, err := f.New(verbose)
	if err != nil {
		base.Vlogf("failed to initialize: %s - %s\n", name, err)
		return nil, err
	}
	if verbose {
		base.Vlogf("using backend: %s\n", name)
	}
	return c, nil
}

func init() {
	factoryNames = make([]string, 0, 2)
	registerFactory(&upnp.ClientFactory{})
	registerFactory(&natpmp.ClientFactory{})
}
