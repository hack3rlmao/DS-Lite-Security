#!/usr/bin/python3
"""
Server-Router for DS-Lite testbed.

Role in DS-Lite:
  The Server-Router sits between the AFTR and the Server. It routes IPv4
  traffic in both directions:
    - AFTR  -> Server: de-NATed packets from B4 clients heading to the server
    - Server -> AFTR:  reply packets going back through the DS-Lite tunnel

  In the testbed topology:
    ens3 (if_aftr)   -- connected to 172.16.0.0/30 network with AFTR
    ens4 (if_server) -- connected to 10.1.0.0/16  network with Server

  This node only enables IP forwarding -- it does NOT perform NAT.
  NAT44 is done exclusively on the AFTR. The Server-Router is a pure L3
  router with directly connected routes on both interfaces.

  With -ia_ip and -is_ip parameters, the script assigns IP addresses to
  both interfaces automatically -- no manual 'ip addr add' needed.
  With -client_gw and -client_net, it also adds the return route to B4 LANs.
"""

import argparse
import subprocess
import sys
import netifaces
import signal

from validate_parameters import is_valid_ipv4_network, is_valid_num

# -- Global state -------------------------------------------------------------
if_aftr_global   = None  # interface towards AFTR
if_server_global = None  # interface towards Server

def signal_handler(sig, frame):
    print("\n---> Keyboard Interrupt. Cleaning up...")
    cleanup()
    sys.exit(0)

def cleanup():
    """Disables IPv4 forwarding on exit."""
    global if_aftr_global, if_server_global

    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("Cleanup completed.")


def parameter():
    """Parses and validates CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Server-Router for DS-Lite - routes between AFTR and Server.")

    parser.add_argument("-ia", dest="if_aftr", required=True,
                        help="Interface facing the AFTR node (e.g. ens3).")
    parser.add_argument("-is", dest="if_server", required=True,
                        help="Interface facing the Server node (e.g. ens4).")
    parser.add_argument("-ia_ip", dest="ia_ip",
                        help="IPv4 address to assign to the AFTR-facing interface "
                             "(e.g. 172.16.0.2/30). Assigned automatically at startup.")
    parser.add_argument("-is_ip", dest="is_ip",
                        help="IPv4 address to assign to the Server-facing interface "
                             "(e.g. 10.1.0.254/16). Assigned automatically at startup.")
    parser.add_argument("-client_gw", dest="client_gw",
                        help="IPv4 gateway on the AFTR side for return routes to B4 LANs "
                             "(e.g. 172.16.0.1). Used together with -client_net.")
    parser.add_argument("-client_net", dest="client_net", default="192.168.0.0/16",
                        help="IPv4 network(s) of B4 clients. A return route is added via "
                             "-client_gw. Default: 192.168.0.0/16")
    parser.add_argument("-aftr_net", dest="aftr_net", default="10.0.0.0/8",
                        help="IPv4 network on the AFTR side. Default: 10.0.0.0/8")
    parser.add_argument("-server_net", dest="server_net", default="10.1.0.0/16",
                        help="IPv4 network on the Server side. Default: 10.1.0.0/16")

    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    flag = False
    interface_list = netifaces.interfaces()

    if args.if_aftr not in interface_list:
        print("AFTR interface invalid!")
        flag = True

    if args.if_server not in interface_list:
        print("Server interface invalid!")
        flag = True

    if not is_valid_ipv4_network(args.aftr_net):
        print("AFTR network invalid!")
        flag = True

    if not is_valid_ipv4_network(args.server_net):
        print("Server network invalid!")
        flag = True

    if flag:
        sys.exit(1)

    return (args.if_aftr, args.if_server, args.ia_ip, args.is_ip,
            args.client_gw, args.client_net, args.aftr_net, args.server_net)


def assign_interface_ip(interface, ip_with_prefix):
    """
    Assigns an IPv4 address to an interface, flushing existing addresses first.

    ip_with_prefix -- e.g. "172.16.0.2/30"
    """
    try:
        subprocess.run(["ip", "addr", "flush", "dev", interface],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "add", ip_with_prefix, "dev", interface],
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"IP {ip_with_prefix} assigned to {interface}.")
    except subprocess.CalledProcessError as e:
        print(f"ERROR assigning IP to {interface}: {e}")
        sys.exit(1)


def add_client_return_route(network, gateway, interface):
    """
    Adds a route back to B4 client networks via the AFTR gateway.
    This is necessary so that reply packets from the server network
    can find their way back to the B4 LANs through the AFTR.

    network   -- e.g. "192.168.0.0/16"
    gateway   -- e.g. "172.16.0.1" (AFTR's IPv4 address)
    interface -- AFTR-facing interface (e.g. ens3)
    """
    try:
        subprocess.run(["ip", "route", "add", network, "via", gateway, "dev", interface],
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Return route {network} via {gateway} added.")
    except subprocess.CalledProcessError as e:
        print(f"Route {network} error (may already exist): {e}")


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
    Enables IPv4 forwarding so the kernel routes packets between
    the AFTR-facing and Server-facing interfaces.
    """
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    print("Traffic forwarding enabled.")


# -- Main ---------------------------------------------------------------------
try:
    (if_aftr, if_server, ia_ip, is_ip,
     client_gw, client_net, aftr_net, server_net) = parameter()

    if_aftr_global   = if_aftr
    if_server_global = if_server

    signal.signal(signal.SIGINT, signal_handler)

    print("\n" + "="*60)
    print("   Server-Router Configuration")
    print("="*60)
    print(f"AFTR Interface:   {if_aftr}")
    print(f"Server Interface: {if_server}")
    if ia_ip:
        print(f"AFTR-side IP:     {ia_ip}")
    if is_ip:
        print(f"Server-side IP:   {is_ip}")
    if client_gw:
        print(f"Client Gateway:   {client_gw}")
        print(f"Client Network:   {client_net}")
    print("="*60 + "\n")

    # Step 1: Bring both interfaces up
    check_and_enable_interface(if_aftr)
    check_and_enable_interface(if_server)

    # Step 2: Assign IP addresses to interfaces if provided
    if ia_ip:
        assign_interface_ip(if_aftr, ia_ip)

    if is_ip:
        assign_interface_ip(if_server, is_ip)

    # Step 3: Add return route to B4 client networks via AFTR
    if client_gw and client_net:
        add_client_return_route(client_net, client_gw, if_aftr)

    # Step 4: Enable IPv4 forwarding between the two interfaces
    enable_traffic_forwarding()

    print("\n" + "="*60)
    print("   Server-Router Running")
    print("="*60)
    print("Press Ctrl+C to stop.\n")

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
