/*
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

// Package natclient provides interfaces to various NAT port forwarding
// configuration methods.
package natclient

import (
	"fmt"

	"github.com/yawning/go-fw-helper/natclient/base"
	"github.com/yawning/go-fw-helper/natclient/natpmp"
	"github.com/yawning/go-fw-helper/natclient/upnp"
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

// New attempts to discover and initialize a suitable port forwarding mechanism
// using any of the compatible backends.
func New(verbose bool) (base.Client, error) {
	for _, name := range factoryNames {
		f := factories[name]
		if verbose {
			base.Vlogf("attempting backend: %s\n", name)
		}
		c, err := f.New(verbose)
		if c != nil && err == nil {
			if verbose {
				base.Vlogf("using backend: %s\n", name)
			}
			return c, nil
		} else if verbose {
			base.Vlogf("failed to initialize: %s - %s\n", name, err)
		}
	}
	return nil, fmt.Errorf("failed to initialize/discover a port forwarding mechanism")
}

func init() {
	factoryNames = make([]string, 0, 2)
	registerFactory(&upnp.ClientFactory{})
	registerFactory(&natpmp.ClientFactory{})
}
