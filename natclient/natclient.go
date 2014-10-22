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

func registerFactory(f base.ClientFactory) {
	name := f.Name()
	e := factories[name]
	if e != nil {
		panic(fmt.Sprintf("factory '%s' is already registered", name))
	}
	factories[name] = f
}

// New attempts to discover and initialize a suitable port forwarding mechanism
// using any of the compatible backends.
func New(verbose bool) (base.Client, error) {
	for _, f := range factories {
		if verbose {
			base.Vlogf("attempting backend: %s\n", f.Name())
		}
		c, err := f.New(verbose)
		if c != nil && err == nil {
			if verbose {
				base.Vlogf("using backend: %s\n", f.Name())
			}
			return c, nil
		} else if verbose {
			base.Vlogf("failed to initialize: %s - %s\n", f.Name(), err)
		}
	}
	return nil, fmt.Errorf("failed to initialize/discover a port forwarding mechanism")
}

func init() {
	registerFactory(&upnp.ClientFactory{})
	registerFactory(&natpmp.ClientFactory{})
}
