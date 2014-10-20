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
func New() (base.Client, error) {
	for _, f := range factories {
		c, err := f.New()
		if c != nil && err == nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("failed to initialize/discover a port forwarding mechanism")
}

func init() {
	registerFactory(&upnp.ClientFactory{})
}
