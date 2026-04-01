#!/usr/bin/python3
"""
AFTR (Address Family Transition Router) for DS-Lite (RFC 6333).

Role in DS-Lite:
  The AFTR sits at the service provider edge. It has two interfaces:
    - Tunnel interface (CORE): connected to the IPv6 CORE network
    - Server interface (WAN):  connected to the IPv4 network / internet

  For each known B4 node it creates a dedicated ip6tnl tunnel (per-B4 model).
  When a B4 sends IPv4 traffic encapsulated in IPv6, the AFTR:
    1. Decapsulates the IPv6 header -> gets the original IPv4 packet
    2. Applies NAT44 (MASQUERADE) -> maps B4's private IPv4 to the AFTR's
       public IPv4 and forwards it towards the server/internet

  Return traffic path:
    Server -> AFTR (NAT44 reverse lookup) -> AFTR re-encapsulates in IPv6
    -> sends to the correct B4 via its dedicated tunnel

  Per-B4 tunnel design (vs. single "remote any" tunnel):
    RFC 6333 originally used a single tunnel with 'remote any', but this
    causes issues because the kernel cannot distinguish return traffic per B4.
    Using one dedicated tunnel per B4 (with a specific remote IPv6) gives
    the kernel a unique interface per B4, enabling per-B4 routing and NAT.

  Inter-B4 traffic (B4-1 PC -> B4-2 PC):
    iptables ACCEPT rules are inserted BEFORE the MASQUERADE rule so that
    traffic going back out through another tunnel is not NATed -- it just
    gets re-encapsulated and forwarded.

  With KEA static reservations (-reservations in kea_dhcpv6.py), each B4
    always receives the same IPv6 address after every restart, so the AFTR
    command never changes. Without reservations, B4 addresses are assigned
    dynamically and may change on restart -- AFTR must then be relaunched
    with the updated addresses.

  With -aftr parameter, the script also assigns the AFTR IPv6 address to
  the tunnel interface automatically -- no manual 'ip -6 addr add' needed.
"""

import argparse
import subprocess
import sys
import netifaces
import signal

from validate_parameters import get_ipv6_addresses, is_valid_ipv4_network, \
    is_valid_ipv6, is_valid_num

# -- Global state -------------------------------------------------------------
tunnel_interfaces = []   # list of tunnel interface names created by this run
if_server_global  = None # server-facing interface (for cleanup)
net_client_global = None # client networks (for cleanup)

def signal_handler(sig, frame):
    print("\n---> Keyboard Interrupt. Cleaning up...")
    cleanup()
    sys.exit(0)

def cleanup():
    """Removes iptables rules and all tunnel interfaces."""
    global tunnel_interfaces, if_server_global, net_client_global

    if if_server_global:
        del_iptables_rules(if_server_global)

    for tunnel_name in tunnel_interfaces:
        if check_interface_if_exists(tunnel_name):
            delete_interface_if_exists(tunnel_name)
            print(f"Tunnel {tunnel_name} deleted.")

    print("Cleanup completed.")


def parameter():
    """Parses and validates CLI arguments."""
    parser = argparse.ArgumentParser(
        description="AFTR for DS-Lite - creates per-B4 tunnels and performs NAT44.")

    parser.add_argument("-is", dest="if_server", required=True,
                        help="Server-side interface towards the IPv4 network / "
                             "server-router (e.g. ens4).")
    parser.add_argument("-it", dest="if_tunnel", required=True,
                        help="CORE-side interface towards B4 nodes over IPv6 (e.g. ens3).")
    parser.add_argument("-aftr", dest="aftr_ip",
                        help="AFTR's own IPv6 address on the CORE interface "
                             "(e.g. 2001:db8::10). The address is assigned to -it interface "
                             "automatically. Auto-detected from existing interface addresses "
                             "if omitted (but you must have added it manually first).")
    parser.add_argument("-net", dest="net_client",
                        help="[Legacy] Client IPv4 networks, comma-separated. "
                             "Use -b4nets instead for per-B4 routing.")
    parser.add_argument("-b4nets", dest="b4nets",
                        help="Per-B4 mapping: B4_IPv6:LAN_network pairs, comma-separated. "
                             "Example: 2001:db8::69:192.168.1.0/24,2001:db8::6a:192.168.2.0/24 "
                             "One tunnel is created per entry. MUST match the IPv6 addresses "
                             "currently assigned to B4 nodes by DHCPv6.")
    parser.add_argument("-tn", dest="tunnel_name", default="ipip6",
                        help="Base name for tunnel interfaces. Tunnels are named "
                             "<base>_1, <base>_2, etc. Default: ipip6")
    parser.add_argument("-mtu", dest="mtu", default="1452",
                        help="Tunnel MTU. Default: 1452")
    parser.add_argument("-aftr_ip4", dest="aftr_ip4",
                        help="IPv4 address to assign to the server-side interface "
                             "(e.g. 172.16.0.1/30). Assigned automatically at startup.")
    parser.add_argument("-gw_ip4", dest="gw_ip4",
                        help="IPv4 gateway on the server side (e.g. 172.16.0.2). "
                             "Used to add a route to the server network.")
    parser.add_argument("-server_net", dest="server_net",
                        help="IPv4 network of the server side (e.g. 10.1.0.0/16). "
                             "A route to this network via -gw_ip4 is added automatically.")

    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    flag = False
    interface_list = netifaces.interfaces()

    if args.if_server not in interface_list:
        print("Server interface invalid!")
        flag = True

    if args.if_tunnel not in interface_list:
        print("Tunnel interface invalid!")
        flag = True

    if args.aftr_ip and not is_valid_ipv6(args.aftr_ip):
        print("Invalid AFTR IPv6!")
        flag = True

    if not is_valid_num(args.mtu):
        print("Invalid MTU!")
        flag = True

    if flag:
        sys.exit(1)

    return args.if_server, args.if_tunnel, args.aftr_ip, args.net_client, \
           args.b4nets, args.tunnel_name, int(args.mtu), \
           args.aftr_ip4, args.gw_ip4, args.server_net


def assign_aftr_ipv6(interface, aftr_ipv6):
    """
    Assigns the AFTR IPv6 address to the CORE interface with /64 prefix.

    This step is required so that B4 nodes can reach the AFTR endpoint:
    a B4 sends NDP Neighbor Solicitation for the AFTR address -- without
    this address on the interface, no Neighbor Advertisement is sent back
    and the B4 tunnel setup fails entirely.

    In v2 this had to be done manually before running the script:
      sudo ip -6 addr add 2001:db8::10/64 dev ens3
    Now done automatically when -aftr is specified.
    """
    import ipaddress as _ipa
    # Compute /64 network to derive the correct prefix length
    net64 = _ipa.IPv6Network(f"{aftr_ipv6}/64", strict=False)

    # Flush existing global-scope IPv6 addresses (preserve link-local fe80::)
    subprocess.run(["ip", "-6", "addr", "flush", "dev", interface, "scope", "global"],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        subprocess.run(["ip", "-6", "addr", "add", f"{aftr_ipv6}/64", "dev", interface],
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"AFTR IPv6 {aftr_ipv6}/64 assigned to {interface}.")
    except subprocess.CalledProcessError as e:
        print(f"ERROR assigning AFTR IPv6: {e}")
        sys.exit(1)


def check_and_enable_interface(interface):
    """Brings the interface up if it is currently DOWN."""
    try:
        result = subprocess.run(["ip", "link", "show", interface],
                               capture_output=True, text=True, check=True)
        if "state UP" not in result.stdout:
            subprocess.run(["ip", "link", "set", "dev", interface, "up"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            print(f"Interface {interface} brought up.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def enable_traffic_forwarding():
    """
    Enables IPv4/IPv6 forwarding and disables reverse-path filtering.
    rp_filter=0 is required because decapsulated IPv4 packets arrive on
    the tunnel interface but their source IP belongs to a different subnet
    than what is directly connected -- strict rp_filter would drop them.
    """
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    subprocess.run(["sysctl", "-w", "net.ipv4.conf.all.rp_filter=0"],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Traffic forwarding enabled.")


def add_per_b4_tunnel(local_ip, remote_b4_ip, interface, name, mtu):
    """
    Creates a dedicated ip6tnl tunnel for one specific B4 node.

    local_ip     -- AFTR's IPv6 address (tunnel source)
    remote_b4_ip -- B4's current IPv6 address from DHCPv6 (tunnel destination)
    interface    -- Underlying CORE interface (e.g. ens3)
    name         -- Tunnel name (e.g. ipip6_1)
    mtu          -- Tunnel MTU

    mode ipip6:   DS-Lite encapsulation (IPv4 in IPv6)
    encaplimit 0: No IPv6 Destination Options header (avoids drops on
                  intermediate routers that do not understand unknown options)
    """
    subprocess.run(
        ["ip", "link", "add", "name", name, "mtu", str(mtu),
         "type", "ip6tnl", "local", local_ip, "remote", remote_b4_ip,
         "mode", "ipip6", "dev", interface, "encaplimit", "0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    print(f"Per-B4 tunnel '{name}' created (remote: {remote_b4_ip}).")


def add_route(network, interface):
    """Adds an IPv4 route pointing to the given interface."""
    try:
        subprocess.run(["ip", "route", "add", network, "dev", interface],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        print(f"Route {network} added via {interface}.")
    except Exception as e:
        print(f"Route error (may already exist): {e}")


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


def add_iptables_rules(interface, tunnel_names):
    """
    Sets up NAT44 rules for AFTR:

    1. ACCEPT rules (inserted at position 1, highest priority) for traffic
       going OUT through any B4 tunnel -- this is inter-B4 traffic (e.g.
       B4-1 PC -> B4-2 PC). It must NOT be NATed, just re-encapsulated.

    2. MASQUERADE rule on the server interface -- translates B4 clients'
       private IPv4 addresses (192.168.x.x) to the AFTR's IPv4 address
       before forwarding to the server. This is the core DS-Lite NAT44.
    """
    # ACCEPT before MASQUERADE for inter-B4 traffic (no NAT between B4s)
    for tname in tunnel_names:
        rule = f"iptables -t nat -I POSTROUTING 1 -o {tname} -j ACCEPT"
        subprocess.run(rule, shell=True)
    # NAT44: masquerade all traffic going towards the server
    rule = f"iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE"
    subprocess.run(rule, shell=True, check=True)


def del_iptables_rules(interface):
    """Removes the MASQUERADE rule added by add_iptables_rules."""
    rule = f"iptables -t nat -D POSTROUTING -o {interface} -j MASQUERADE"
    try:
        subprocess.run(rule, shell=True)
    except:
        pass


def configure_server_interface(interface, aftr_ip4, gw_ip4, server_net):
    """
    Assigns IPv4 address to the server-facing interface and adds a route
    to the server network.
    """
    if aftr_ip4:
        try:
            subprocess.run(["ip", "addr", "add", aftr_ip4, "dev", interface],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"IP {aftr_ip4} assigned to {interface}.")
        except:
            pass
    if gw_ip4 and server_net:
        try:
            subprocess.run(["ip", "route", "add", server_net, "via", gw_ip4, "dev", interface],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Route {server_net} via {gw_ip4} added.")
        except:
            pass


# -- Main ---------------------------------------------------------------------
try:
    (if_server, if_tunnel, aftr_ip, net_client, b4nets,
     tunnel_name_base, mtu, aftr_ip4, gw_ip4, server_net) = parameter()

    if_server_global  = if_server
    net_client_global = net_client

    signal.signal(signal.SIGINT, signal_handler)

    check_and_enable_interface(if_server)
    check_and_enable_interface(if_tunnel)

    # Step 1: Assign AFTR IPv6 address to the CORE interface (replaces manual step)
    # In v2 you had to run: sudo ip -6 addr add 2001:db8::10/64 dev ens3
    if aftr_ip:
        assign_aftr_ipv6(if_tunnel, aftr_ip)
    else:
        # No -aftr given: try to auto-detect from existing interface addresses
        ipv6_addrs = get_ipv6_addresses(if_tunnel)
        if ipv6_addrs:
            for addr in ipv6_addrs:
                if not addr.startswith("fe80:"):
                    aftr_ip = addr
                    print(f"Auto-detected AFTR IPv6: {aftr_ip}")
                    break
        if not aftr_ip:
            print("ERROR: AFTR IPv6 required! Use -aftr 2001:db8::10")
            sys.exit(1)

    # Step 2: Assign IPv4 to server-facing interface (if specified)
    if aftr_ip4:
        configure_server_interface(if_server, aftr_ip4, gw_ip4, server_net)

    # Step 3: Parse -b4nets and create one tunnel per B4 node
    # Format: "b4_ipv6:lan_network/mask,b4_ipv6:lan_network/mask,..."
    # The IPv6 address may contain colons; split on the last ':' before the '/'
    b4_list = []
    if b4nets:
        for entry in b4nets.split(','):
            entry = entry.strip()
            if ':' in entry:
                parts = entry.rsplit(':', 1)
                if len(parts) == 2 and '/' in parts[1]:
                    b4_ipv6 = parts[0]
                    b4_lan  = parts[1]
                    b4_list.append((b4_ipv6, b4_lan))
                else:
                    b4_list.append((entry, None))

    if b4_list:
        for i, (b4_ipv6, b4_lan) in enumerate(b4_list, 1):
            tunnel_name = f"{tunnel_name_base}_{i}"

            # Remove stale tunnel from a previous run if present
            if check_interface_if_exists(tunnel_name):
                delete_interface_if_exists(tunnel_name)

            add_per_b4_tunnel(aftr_ip, b4_ipv6, if_tunnel, tunnel_name, mtu)
            check_and_enable_interface(tunnel_name)
            tunnel_interfaces.append(tunnel_name)

            # Add route so return IPv4 traffic is forwarded to the correct B4
            if b4_lan:
                add_route(b4_lan, tunnel_name)

            print(f"B4-{i}: IPv6={b4_ipv6}, LAN={b4_lan}, tunnel={tunnel_name}")

    elif net_client:
        # Legacy fallback: single tunnel with 'remote any' (not recommended)
        tunnel_name = f"{tunnel_name_base}_dynamic"
        if check_interface_if_exists(tunnel_name):
            delete_interface_if_exists(tunnel_name)

        subprocess.run(
            ["ip", "link", "add", "name", tunnel_name, "mtu", str(mtu),
             "type", "ip6tnl", "local", aftr_ip, "remote", "any",
             "mode", "ipip6", "dev", if_tunnel, "encaplimit", "0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        subprocess.run(["ip", "link", "set", tunnel_name, "up"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tunnel_interfaces.append(tunnel_name)

        for net in net_client.split(','):
            add_route(net.strip(), tunnel_name)

    # Step 4: Enable IP forwarding and NAT44
    enable_traffic_forwarding()
    add_iptables_rules(if_server, tunnel_interfaces)

    print("\n" + "="*60)
    print("   AFTR Configuration Complete")
    print("="*60)
    print(f"Server Interface: {if_server}")
    print(f"Tunnel Interface: {if_tunnel}")
    print(f"AFTR IPv6:        {aftr_ip}")
    print(f"Tunnels:          {tunnel_interfaces}")
    print(f"NAT:              Enabled (MASQUERADE on {if_server})")
    print("="*60)
    print("\nRunning... Press Ctrl+C to stop.\n")

    while True:
        pass

except KeyboardInterrupt:
    cleanup()
    sys.exit(0)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    cleanup()
    sys.exit(1)
