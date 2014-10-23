/*
 * Copyright (c) 2010, Jacob Appelbaum, Steven J. Murdoch.
 * Copyright (c) 2010-2013, The Tor Project, Inc.
 * Copyright (c) 2014, The Tor Project, Inc.
 * See LICENSE for licensing information
 */

// go-fw-helper is a tool for opening firewalls with the various NAT traversal
// mechanisms.  This tool is designed as a drop in replacement for
// tor-fw-helper, with less hard-to-audit library code, and the use of a
// memory-safe language as design goals.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/yawning/go-fw-helper/natclient"
)

const (
	mappingDescr    = "Tor relay"
	mappingDuration = 0
	versionString   = "0.1"
)

type portPair struct {
	internal int
	external int
}

type forwardList []portPair

func (l *forwardList) String() string {
	return fmt.Sprint(*l)
}

func (l *forwardList) Set(value string) error {
	var internal, external int

	split := strings.Split(value, ":")
	if len(split) != 2 {
		return fmt.Errorf("failed to parse '%s'", value)
	}

	// Internal port is required, so handle it first.
	tmp, err := strconv.ParseUint(split[1], 10, 16)
	if err != nil {
		return err
	}
	internal = int(tmp)

	// External port is optional.
	if split[0] == "" {
		// If missing, set to the same as internal.
		external = internal
	} else {
		tmp, err := strconv.ParseUint(split[0], 10, 16)
		if err != nil {
			return err
		}
		external = int(tmp)
	}

	*l = append(*l, portPair{internal, external})
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "%s usage:\n"+
		" [-h|--help]\n"+
		" [-T|--test-commandline]\n"+
		" [-v|--verbose]\n"+
		" [-g|--fetch-public-ip]\n"+
		" [-p|--forward-port ([<external port>]:<internal port>)]\n", os.Args[0])
	os.Exit(1)
}

func main() {
	doHelp := false
	doTest := false
	isVerbose := false
	doFetchIP := false
	var portsToForward forwardList

	// So, the flag package kind of sucks and doesn't gracefully support the
	// concept of aliased flags when printing usage, which results in a
	// usage and help output that looks like crap.  Fix this by ignoring the
	// flag package's built in usage support, and overriding Usage().
	flag.Usage = usage
	flag.BoolVar(&doHelp, "help", false, "")
	flag.BoolVar(&doHelp, "h", false, "")
	flag.BoolVar(&doTest, "test-commandline", false, "")
	flag.BoolVar(&doTest, "T", false, "")
	flag.BoolVar(&isVerbose, "verbose", false, "")
	flag.BoolVar(&isVerbose, "v", false, "")
	flag.BoolVar(&doFetchIP, "fetch-public-ip", false, "")
	flag.BoolVar(&doFetchIP, "g", false, "")
	flag.Var(&portsToForward, "forward-port", "")
	flag.Var(&portsToForward, "p", "")
	flag.Parse()

	// Extra flag related handling.
	if doHelp || flag.NArg() > 0 {
		usage()
	}
	if isVerbose {
		// Dump information about how we were invoked.
		fmt.Fprintf(os.Stderr, "V: go-fw-helper version %s\n"+
			"V: We were called with the following arguments:\n"+
			"V: verbose = %v, help = %v, fetch_public_ip = %v\n",
			versionString, isVerbose, doHelp, doFetchIP)

		if len(portsToForward) > 0 {
			fmt.Fprintf(os.Stderr, "V: TCP forwarding:\n")
			for _, ent := range portsToForward {
				fmt.Fprintf(os.Stderr, "V: External %v, Internal: %v\n",
					ent.external, ent.internal)
			}
		}
	}
	if doTest {
		// If the app is being called in test mode, dump the command line
		// arguments to a file.
		//
		// TODO: I have no idea why this exists, I'll add this later.
		fmt.Fprintf(os.Stderr, "E: --test-commandline not implemented yet\n")
		os.Exit(1)
	}
	if len(portsToForward) == 0 && !doFetchIP {
		// Nothing to do, sad panda.
		fmt.Fprintf(os.Stderr, "E: We require a port to be forwarded or "+
			"fetch_public_ip request!\n")
		os.Exit(1)
	}

	// Discover/Initialize a compatible NAT traversal method.
	c, err := natclient.New(isVerbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "E: %s\n", err)
		os.Exit(1)
	}
	defer c.Close()

	// Forward some ports, the response is delivered over stdout in a
	// predefined format.
	for _, pair := range portsToForward {
		err = c.AddPortMapping(mappingDescr, pair.internal, pair.external, mappingDuration)
		if err != nil {
			c.Vlogf("AddPortMapping() failed: %s\n", err)
			fmt.Fprintf(os.Stdout, "tor-fw-helper tcp-forward %d %d FAIL\n", pair.external, pair.internal)
		} else {
			c.Vlogf("AddPortMapping() succeded\n")
			fmt.Fprintf(os.Stdout, "tor-fw-helper tcp-forward %d %d SUCCESS\n", pair.external, pair.internal)
		}
		os.Stdout.Sync()
	}

	// Get the external IP.
	if doFetchIP {
		ip, err := c.GetExternalIPAddress()
		if err != nil {
			fmt.Fprintf(os.Stderr, "E: Failed to query the external IP address: %s", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "go-fw-helper: ExternalIPAddress = %s\n", ip)
	}
}
