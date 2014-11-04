### tor-fw-helper - Go language tor-fw-helper rewrite.
#### Yawning Angel (yawning at torproject dot org)

This is a tor-fw-helper rewrite in Go that functions as a drop in replacement
for the original C code.

Features:
 * Interface compatibility with the C tor-fw-helper.
 * UPnP based NAT traversal.
 * NAT-PMP based NAT traversal.

Limitations:
 * go-fw-helper's "-T" option does not write to the log file.
 * As the helper needs to be able to receive UDP packets, the local firewall's
   config may need to be altered.
 * Lease times are hardcoded to "0" for UPnP (Indefinite/1 week depending on
   the UPnP version) and 7200 seconds for NAT-PMP.  RFC 6886 includes dire
   warnings about broken UPnP implementations that freak out for non-"0" lease
   times.

TODO:
 * Maybe also support PCP.  Technically everything that speaks PCP should also
   speak NAT-PMP, so this is relatively low priority.

Further Reading:
 * http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0-20080424.pdf
 * http://www.upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.1.pdf
 * http://www.upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v2-Device.pdf
 * http://www.upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf
 * https://tools.ietf.org/html/rfc6886
