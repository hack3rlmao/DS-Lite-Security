#!/usr/bin/python3
"""
B4 (Basic Bridging BroadBand) element for DS-Lite (RFC 6333).

Role in DS-Lite:
  The B4 element sits at the customer edge. It has two interfaces:
    - Tunnel interface (WAN/CORE): connected to the IPv6-only CORE network
    - Client interface (LAN):     connected to the local IPv4 LAN (PCs)

  Startup sequence:
    1. Optionally assign IPv4 address to the LAN interface (-lan_ip)
    2. Run dhclient -6 on the tunnel interface -> gets IPv6 address + AFTR-Name
       (DHCPv6 option 64, RFC 6334) from the DHCPv6 server
    3. Resolve the AFTR FQDN to an IPv6 address via DNS
    4. Create an ip6tnl tunnel (mode ipip6): encapsulates IPv4 packets inside
       IPv6 so they can traverse the IPv6-only CORE network
    5. Optionally add cross-B4 routes (-cross_routes) via the tunnel
    6. Optionally start dnsmasq to hand out IPv4 addresses to LAN clients

  Tunnel mode details:
    - Type: ip6tnl, mode: ipip6  (IPv4-in-IPv6, as required by DS-Lite RFC 6333)
    - encaplimit 0: disables the IPv6 destination option header that normally
      triggers "Unknown option" drops on intermediate routers
    - MTU 1452: accounts for 40-byte IPv6 header overhead on top of a
      typical 1500-byte Ethernet MTU
"""

import argparse
import subprocess
import sys
import netifaces
import signal
import os
import time
import re

from validate_parameters import add_ipv6_address, get_ipv4_addresses, \
    get_ipv6_addresses, is_valid_ipv4_network, is_valid_ipv4_range, is_valid_num

# -- Global state -------------------------------------------------------------
tunnel_name_global      = None   # tunnel interface name (e.g. ipip6_b4_1)
if_client_global        = None   # LAN interface name
net_server_global       = None   # IPv4 network routed via tunnel
b4_ip_global            = None   # This B4's IPv6 address (from DHCPv6)
aftr_ip_global          = None   # AFTR's IPv6 address (resolved from FQDN)
if_tunnel_global        = None   # WAN/CORE interface name
mtu_global              = None   # Tunnel MTU
dhcp_process            = None   # subprocess handle for dnsmasq DHCPv4
dhcpv6_client_process   = None   # subprocess handle for dhclient -6

def signal_handler(sig, frame):
    print("\n---> Keyboard Interrupt. Cleaning up...")
    cleanup()
    sys.exit(0)

def cleanup():
    """Stops dhclient and dnsmasq, removes the tunnel interface and routes."""
    global dhcp_process, dhcpv6_client_process

    if dhcpv6_client_process:
        try:
            dhcpv6_client_process.terminate()
            dhcpv6_client_process.wait(timeout=3)
            print("DHCPv6 client stopped.")
        except:
            pass

    if dhcp_process:
        try:
            dhcp_process.terminate()
            dhcp_process.wait(timeout=3)
            print("DHCPv4 server stopped.")
        except:
            pass

    # Remove DHCPv4 lease file
    for f in ["/tmp/dnsmasq_b4.leases"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass

    # Remove route that was added via the tunnel
    if net_server_global and tunnel_name_global:
        try:
            del_route(net_server_global, tunnel_name_global)
        except:
            pass

    # Remove the tunnel interface itself
    if tunnel_name_global and check_interface_if_exists(tunnel_name_global):
        try:
            delete_interface_if_exists(tunnel_name_global)
        except:
            pass

    print("Cleanup completed.")


def assign_lan_ip(interface, ip_with_prefix):
    """
    Assigns an IPv4 address to the LAN interface.
    Replaces any existing address on the interface first to avoid conflicts.

    ip_with_prefix -- e.g. "192.168.1.1/24"
    """
    try:
        subprocess.run(["ip", "addr", "flush", "dev", interface],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "add", ip_with_prefix, "dev", interface],
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"LAN IP {ip_with_prefix} assigned to {interface}.")
    except subprocess.CalledProcessError as e:
        print(f"ERROR assigning LAN IP: {e}")
        sys.exit(1)


def add_cross_routes(routes_str, tunnel_iface):
    """
    Adds routes to other B4 LAN networks via the tunnel interface.
    These routes allow traffic between B4-1 LAN and B4-2 LAN to flow
    through the AFTR without going through the public internet.

    routes_str  -- comma-separated networks, e.g. "192.168.2.0/24,192.168.3.0/24"
    tunnel_iface -- tunnel interface name (e.g. ipip6_b4_1)
    """
    for route in routes_str.split(','):
        route = route.strip()
        if not route:
            continue
        try:
            subprocess.run(["ip", "route", "add", route, "dev", tunnel_iface],
                          check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Cross-B4 route {route} added via {tunnel_iface}.")
        except subprocess.CalledProcessError as e:
            print(f"Route {route} error (may already exist): {e}")


def start_dhcpv6_client(interface, timeout=15):
    """
    Runs dhclient -6 on the tunnel (WAN) interface and waits for a lease.

    Steps:
      1. Remove any stale lease file so dhclient fetches a fresh one
         (stale leases may contain old DNS servers without the local
          dnsmasq entry needed to resolve the AFTR FQDN)
      2. Launch 'dhclient -6' and wait for the configured timeout
      3. Parse the lease file for:
           - iaaddr: the assigned IPv6 address
           - dhcp6.name-servers: DNS servers (used to query AFTR FQDN)
           - dhcp6.aftr-name: the AFTR FQDN (DHCPv6 option 64)
      4. Assign the IPv6 address to the interface with /64 prefix
         AND add a /64 network route -- without the route, the interface
         only has a /128 host route and cannot reach the DNS server
      5. Resolve the AFTR FQDN using 'dig' against each nameserver in the lease
         Falls back to 'getent ahostsv6' if dig returns nothing

    AppArmor note:
      On Ubuntu, AppArmor restricts dhclient to write lease files only to
      /var/lib/dhcp/. Custom paths (-lf flag) are blocked even with sudo.
      We therefore let dhclient use its default path and read from there.

    Returns:
      (b4_ipv6_string, aftr_ipv6_string) or (None, None) on failure
    """
    global dhcpv6_client_process, b4_ip_global, aftr_ip_global

    print(f"Requesting IPv6 and AFTR-Name via DHCPv6 on {interface}...")

    # Delete stale lease file to force dhclient to request a new one.
    # This ensures the new lease contains the current DNS server list
    # (which includes the local dnsmasq that knows the AFTR FQDN).
    lease_file = "/var/lib/dhcp/dhclient6.leases"
    try:
        os.remove(lease_file)
    except OSError:
        pass

    try:
        # Launch dhclient without -lf/-df flags (AppArmor restriction)
        dhcpv6_client_process = subprocess.Popen(
            ["dhclient", "-6", "-v", interface],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        # Wait for dhclient to complete the Solicit->Advertise->Request->Reply exchange
        time.sleep(timeout)

        b4_ip    = None
        aftr_fqdn = None

        try:
            with open("/var/lib/dhcp/dhclient6.leases", "r") as f:
                content = f.read()

                # -- Extract IPv6 address -------------------------------------
                ipv6_match = re.search(r'iaaddr\s+([0-9a-f:]+)', content, re.IGNORECASE)
                if ipv6_match:
                    b4_ip = ipv6_match.group(1)
                    print(f"v DHCPv6 assigned: {b4_ip}")

                    # Assign the address with /64 prefix so the kernel creates
                    # a proper on-link route for the 2001:db8::/64 subnet.
                    subprocess.run(
                        ["ip", "-6", "addr", "replace", f"{b4_ip}/64", "dev", interface],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )

                    # Also explicitly add the /64 network route.
                    # dhclient may have added only a /128 host route; without the
                    # /64 prefix route, 'dig @2001:db8::1' returns "network unreachable".
                    import ipaddress as _ipa
                    net64 = str(_ipa.IPv6Network(f"{b4_ip}/64", strict=False))
                    subprocess.run(
                        ["ip", "-6", "route", "add", net64, "dev", interface],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )

                # -- Extract nameservers (needed to query AFTR FQDN) ----------
                # Lease format uses "option dhcp6.name-servers" prefix
                ns_match = re.search(r'option (?:dhcp6\.)?name-servers\s+([^\s;]+)',
                                     content, re.IGNORECASE)
                nameservers = []
                if ns_match:
                    nameservers = [s.strip() for s in ns_match.group(1).split(',')]

                # -- Extract AFTR-Name (DHCPv6 option 64) ---------------------
                # Lease file stores it as: option dhcp6.aftr-name "aftr.dslite.local."
                # Note the trailing dot -- standard FQDN notation; strip it for dig/getent.
                aftr_match = re.search(r'option (?:dhcp6\.)?aftr-name\s+"([^"]+)"',
                                       content, re.IGNORECASE)
                if aftr_match:
                    aftr_fqdn = aftr_match.group(1).rstrip('.')
                    print(f"v AFTR-Name: {aftr_fqdn}")

                    # Try resolving AFTR FQDN to IPv6 via each nameserver
                    for ns in nameservers:
                        try:
                            result = subprocess.run(
                                ["dig", "AAAA", aftr_fqdn, f"@{ns}", "+short", "+timeout=3"],
                                capture_output=True, text=True, timeout=5
                            )
                            for line in result.stdout.strip().split('\n'):
                                line = line.strip()
                                # Accept only valid IPv6 addresses (no trailing dots etc.)
                                if re.match(r'^[0-9a-f:]+$', line):
                                    aftr_ip_global = line
                                    print(f"v AFTR IPv6: {aftr_ip_global} (via {ns})")
                                    break
                            if aftr_ip_global:
                                break
                        except Exception:
                            continue

                    # Fallback: use getent (queries /etc/hosts and system resolver)
                    if not aftr_ip_global:
                        try:
                            result = subprocess.run(
                                ["getent", "ahostsv6", aftr_fqdn],
                                capture_output=True, text=True
                            )
                            for line in result.stdout.split('\n'):
                                ipv6 = re.match(r'([0-9a-f:]+)', line)
                                if ipv6:
                                    aftr_ip_global = ipv6.group(1)
                                    print(f"v AFTR IPv6: {aftr_ip_global} (getent)")
                                    break
                        except Exception as e:
                            print(f"DNS resolution failed: {e}")
        except Exception as e:
            print(f"Warning: Could not parse lease: {e}")

        # Last resort: pick any non-link-local IPv6 from the interface
        if not b4_ip:
            ipv6_addrs = get_ipv6_addresses(interface)
            if ipv6_addrs:
                for addr in ipv6_addrs:
                    if not addr.startswith("fe80:"):
                        b4_ip = addr
                        print(f"v Got IPv6: {b4_ip}")
                        break

        b4_ip_global = b4_ip
        return b4_ip, aftr_ip_global

    except FileNotFoundError:
        print("ERROR: dhclient not found! Install: apt install isc-dhcp-client")
        return None, None
    except Exception as e:
        print(f"ERROR: {e}")
        return None, None


def start_dhcp_server(interface, dhcp_range, lease_time="1h",
                      dns_server=None, gateway=None):
    """
    Starts dnsmasq as a DHCPv4 server on the LAN (client) interface.

    Provides IPv4 addresses to local PCs so they can communicate over the
    DS-Lite tunnel without needing manual IP configuration.

    The DHCP range format accepted by this function is either:
      - "192.168.1.100-192.168.1.200"  (hyphen-separated, as passed on CLI)
      - "192.168.1.100,192.168.1.200"  (comma-separated, dnsmasq native format)
    Both are normalized to the comma format that dnsmasq -F requires.
    """
    global dhcp_process

    # Use the interface's own IPv4 address as gateway if not specified
    if not gateway:
        ipv4_addrs = get_ipv4_addresses(interface)
        if ipv4_addrs:
            gateway = ipv4_addrs[0].split('/')[0]
            print(f"Using gateway: {gateway}")

    if not dns_server:
        dns_server = gateway

    # Normalize range format: "start-end" -> "start,end,lease"
    # dnsmasq -F flag expects comma-separated values; CLI input uses hyphen.
    dhcp_range_dnsmasq = (dhcp_range.replace('-', ',', 1)
                          if '-' in dhcp_range and ',' not in dhcp_range
                          else dhcp_range)
    dhcp_range_dnsmasq = f"{dhcp_range_dnsmasq},{lease_time}"

    cmd = [
        "dnsmasq", "-i", interface,
        "-F", dhcp_range_dnsmasq,
        f"--dhcp-option=3,{gateway}",    # option 3 = default gateway
        f"--dhcp-option=6,{dns_server}", # option 6 = DNS server
        "--no-daemon", "--bind-interfaces"
    ]

    print(f"Starting DHCPv4 server: {dhcp_range}...")

    try:
        dhcp_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)

        if dhcp_process.poll() is None:
            print("DHCPv4 server started.")
            return True
        else:
            _, stderr = dhcp_process.communicate()
            print(f"DHCPv4 failed: {stderr.decode()}")
            return False
    except Exception as e:
        print(f"ERROR: {e}")
        return False


def parameter():
    """Parses and validates CLI arguments."""
    parser = argparse.ArgumentParser(
        description="B4 node for DS-Lite - gets IPv6 and AFTR from DHCPv6.")

    parser.add_argument("-ic", dest="if_client", required=True,
                        help="Client (LAN) interface connected to local PCs (e.g. ens3).")
    parser.add_argument("-it", dest="if_tunnel", required=True,
                        help="Tunnel (WAN/CORE) interface connected to the IPv6 CORE network "
                             "(e.g. ens4). DHCPv6 is run on this interface.")
    parser.add_argument("-lan_ip", dest="lan_ip",
                        help="IPv4 address to assign to the LAN interface (e.g. 192.168.1.1/24). "
                             "If omitted, you must set the address manually before running.")
    parser.add_argument("-net", dest="net_server",
                        help="IPv4 network reachable via the DS-Lite tunnel (e.g. 10.0.0.0/8). "
                             "A route to this network is added via the tunnel interface.")
    parser.add_argument("-cross_routes", dest="cross_routes",
                        help="Comma-separated IPv4 networks of other B4 LANs to route via tunnel "
                             "(e.g. 192.168.2.0/24). Added after tunnel is up. "
                             "Replaces the manual 'ip route add' step in a second terminal.")
    parser.add_argument("-tn", dest="tunnel_name", default="ipip6",
                        help="Name for the ip6tnl tunnel interface. Default: ipip6. "
                             "Use a unique name per B4 node (e.g. ipip6_b4_1).")
    parser.add_argument("-mtu", dest="mtu", default="1452",
                        help="Tunnel MTU. Default: 1452 (1500 - 40 IPv6 header - 8 overhead).")
    parser.add_argument("-dhcp", dest="dhcp_range",
                        help="DHCPv4 address range for LAN clients "
                             "(e.g. 192.168.1.100-192.168.1.200). "
                             "Requires the client interface to have an IPv4 address "
                             "(set via -lan_ip or manually).")
    parser.add_argument("-dns", dest="dns_server",
                        help="DNS server IP to hand out to DHCPv4 clients. "
                             "Defaults to the client interface gateway if omitted.")
    parser.add_argument("-lease", dest="lease_time", default="1h",
                        help="DHCPv4 lease time (e.g. 1h, 30m). Default: 1h")
    parser.add_argument("-dhcpv6-timeout", dest="dhcpv6_timeout", type=int, default=15,
                        help="Seconds to wait for DHCPv6 reply before giving up. Default: 15")

    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    flag = False
    interface_list = netifaces.interfaces()

    if args.if_client not in interface_list:
        print("Client interface invalid!")
        flag = True

    if args.if_tunnel not in interface_list:
        print("Tunnel interface invalid!")
        flag = True

    if args.net_server and not is_valid_ipv4_network(args.net_server):
        print("Server network invalid!")
        flag = True

    if args.dhcp_range and not is_valid_ipv4_range(args.dhcp_range):
        print("DHCP range invalid!")
        flag = True

    if not is_valid_num(args.mtu):
        print("MTU invalid!")
        flag = True

    if flag:
        sys.exit(1)

    return (args.if_client, args.if_tunnel, args.lan_ip, args.net_server,
            args.cross_routes, args.tunnel_name, int(args.mtu), args.dhcp_range,
            args.dns_server, args.lease_time, args.dhcpv6_timeout)


def check_and_enable_interface(interface):
    """Brings the interface up if it is currently DOWN."""
    try:
        result = subprocess.run(["ip", "link", "show", interface],
                               capture_output=True, text=True, check=True)
        if "state UP" not in result.stdout:
            subprocess.run(["ip", "link", "set", "dev", interface, "up"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Interface {interface} up.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def enable_traffic_forwarding():
    """
    Enables IPv4 and IPv6 forwarding so the B4 node can route between
    the LAN interface and the tunnel interface.
    Required for NAT/routing between local PCs and the tunnel.
    """
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Forwarding enabled.")


def add_ipv6_tunnel(local_ip, remote_ip, interface, name, mtu):
    """
    Creates the DS-Lite ip6tnl tunnel interface.

    Parameters:
      local_ip  -- This B4's IPv6 address (tunnel source, obtained via DHCPv6)
      remote_ip -- AFTR's IPv6 address   (tunnel destination, resolved via DNS)
      interface -- Underlying CORE interface the tunnel rides on (e.g. ens4)
      name      -- Tunnel interface name (e.g. ipip6_b4_1)
      mtu       -- Tunnel MTU (typically 1452)

    Key flags:
      type ip6tnl mode ipip6 -- DS-Lite encapsulation: IPv4 inside IPv6
      encaplimit 0           -- Do not add IPv6 Destination Options header;
                               without this, intermediate routers may drop
                               packets with "Unknown option" errors
    """
    subprocess.run(
        ["ip", "link", "add", "name", name, "mtu", str(mtu),
         "type", "ip6tnl", "local", local_ip, "remote", remote_ip,
         "mode", "ipip6", "dev", interface, "encaplimit", "0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    print(f"Tunnel '{name}' created.")


def add_route(network, interface):
    """Adds an IPv4 route via the given interface (typically the tunnel)."""
    try:
        subprocess.run(["ip", "route", "add", network, "dev", interface],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Route {network} added.")
    except Exception as e:
        print(f"Route error: {e}")


def del_route(network, interface):
    try:
        subprocess.run(["ip", "route", "del", network, "dev", interface],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass


def check_interface_if_exists(name):
    try:
        subprocess.run(["ip", "link", "show", name], check=True,
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except:
        return False


def delete_interface_if_exists(name):
    try:
        subprocess.run(["ip", "link", "delete", name], check=True)
    except:
        pass


# -- Main ---------------------------------------------------------------------
try:
    (if_client, if_tunnel, lan_ip, net_server, cross_routes,
     tunnel_name, mtu, dhcp_range, dns_server, lease_time,
     dhcpv6_timeout) = parameter()

    # Store in globals for use in cleanup()
    globals().update({
        'tunnel_name_global': tunnel_name, 'if_client_global': if_client,
        'net_server_global': net_server,   'if_tunnel_global': if_tunnel,
        'mtu_global': mtu
    })

    signal.signal(signal.SIGINT, signal_handler)

    print("\n" + "="*60)
    print("   B4 Node - DS-Lite")
    print("="*60)
    print(f"Client Interface: {if_client}")
    print(f"Tunnel Interface: {if_tunnel}")
    if lan_ip:
        print(f"LAN IP:           {lan_ip}")
    if cross_routes:
        print(f"Cross-B4 Routes:  {cross_routes}")
    print("="*60 + "\n")

    # Step 1: Ensure both interfaces are UP
    check_and_enable_interface(if_client)
    check_and_enable_interface(if_tunnel)

    # Step 2: Assign LAN IPv4 address if provided via -lan_ip
    if lan_ip:
        assign_lan_ip(if_client, lan_ip)

    # Step 3: Get IPv6 address and AFTR-Name via DHCPv6
    b4_ip, aftr_ip = start_dhcpv6_client(if_tunnel, dhcpv6_timeout)

    if not b4_ip or not aftr_ip:
        print("ERROR: Failed to get IPv6 or AFTR from DHCPv6!")
        cleanup()
        sys.exit(1)

    # Step 4: Create the DS-Lite tunnel (ip6tnl, mode ipip6)
    if check_interface_if_exists(tunnel_name):
        delete_interface_if_exists(tunnel_name)  # clean up stale tunnel from previous run

    add_ipv6_tunnel(b4_ip, aftr_ip, if_tunnel, tunnel_name, mtu)
    check_and_enable_interface(tunnel_name)

    # Step 5: Add route to server network via the tunnel
    if net_server:
        add_route(net_server, tunnel_name)

    # Step 6: Add cross-B4 routes (routes to other B4 LANs) via the tunnel
    if cross_routes:
        add_cross_routes(cross_routes, tunnel_name)

    # Step 7: Enable IP forwarding (LAN <-> tunnel)
    enable_traffic_forwarding()

    # Step 8: Start DHCPv4 server for LAN clients (optional)
    if dhcp_range:
        ipv4_addrs = get_ipv4_addresses(if_client)
        if not ipv4_addrs:
            print(f"ERROR: {if_client} needs IPv4 address!")
            print(f"  Either use -lan_ip 192.168.1.1/24 or run manually:")
            print(f"  ip addr add 192.168.1.1/24 dev {if_client}")
            cleanup()
            sys.exit(1)

        start_dhcp_server(if_client, dhcp_range, lease_time, dns_server)

    print("\n" + "="*60)
    print("   B4 Configuration Complete")
    print("="*60)
    print(f"B4 IPv6:   {b4_ip}")
    print(f"AFTR IPv6: {aftr_ip}")
    print(f"Tunnel:    {tunnel_name}")
    if dhcp_range:
        print(f"DHCPv4:    {dhcp_range}")
    if cross_routes:
        print(f"Cross-B4:  {cross_routes}")
    print("="*60)
    print("\nRunning... Press Ctrl+C to stop.\n")

    while True:
        time.sleep(1)

except KeyboardInterrupt:
    cleanup()
    sys.exit(0)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    cleanup()
    sys.exit(1)
