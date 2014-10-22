### go-fw-helper - tor-fw-helper, with extra safety.
#### Yawning Angel (yawning at torproject dot org)

go-fw-helper is designed as a drop-in replacement for tor-fw-helper.

Features:
 * Compatibility with tor-fw-helper, with a few exceptions.
 * UPnP based NAT traversal.
 * NAT-PMP based NAT traversal.

Differences between go-fw-helper and tor-fw-helper:
 * tor-fw-helper uses permanent leases which can lead to really bad things
   happening in certain enviornments.  go-fw-helper uses 480 second leases (tor
   invokes the helper every 300 seconds, and will retry at 60 second intervals
   if the helper ever fails).
 * go-fw-helper's "-T" option does not write to the log file.

Limitations:
 * NAT-PMP is only supported on Linux for now.
 * As the helper needs to be able to receive UDP packets, the local firewall's
   config may need to be altered. 

TODO:
 * Per RFC6886, using a lease duration other than 0 has been known to crash
   routers, so the UPnP least time should probably be changed back to "0", even
   though the table getting full also causes horrific things to happen.
 * BSD and Windows NAT-PMP support.

Further Reading:
 * http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0-20080424.pdf
 * http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf
 * http://www.upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v2-Device.pdf
 * http://www.upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf
 * https://tools.ietf.org/html/rfc6886
