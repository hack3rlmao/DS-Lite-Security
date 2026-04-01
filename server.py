#!/usr/bin/python3
"""
Server for DS-Lite testbed.

Role in DS-Lite:
  Simulates an internet server reachable from B4 LAN clients via the
  DS-Lite tunnel chain: PC -> B4 -> ip6tnl -> AFTR -> NAT44 -> Server-Router -> Server

  This node:
    - Configures its own IPv4 address on the network interface
    - Starts a minimal HTTP server to verify end-to-end connectivity
    - Optionally adds return routes to B4 LAN networks via -gw parameter
      (replaces the manual 'ip route add' step in a second terminal)
"""

import argparse
import subprocess
import sys
import netifaces
import signal

from validate_parameters import is_valid_ipv4_network

# -- Global state -------------------------------------------------------------
if_server_global = None  # server network interface

def signal_handler(sig, frame):
    print("\n---> Keyboard Interrupt. Cleaning up...")
    cleanup()
    sys.exit(0)

def cleanup():
    """Stops the HTTP server process."""
    global if_server_global

    subprocess.run(["pkill", "-f", "python3 -m http.server"],
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print("Cleanup completed.")


def parameter():
    """Parses and validates CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Server for DS-Lite testbed - simulates internet server.")

    parser.add_argument("-i", dest="if_server", required=True,
                        help="Network interface connected to the server network (e.g. ens3).")
    parser.add_argument("-net", dest="server_net", default="10.1.0.0/16",
                        help="Server network IPv4 range (informational). Default: 10.1.0.0/16")
    parser.add_argument("-ip", dest="server_ip", default="10.0.0.1",
                        help="IPv4 address to assign to the interface. Default: 10.0.0.1")
    parser.add_argument("-web", dest="web_port", type=int, default=80,
                        help="Port for the HTTP test server. "
                             "Test with: curl http://<server_ip>/. Default: 80")
    parser.add_argument("-gw", dest="gateway",
                        help="IPv4 gateway (Server-Router) for adding return routes to B4 LANs "
                             "(e.g. 10.1.0.254). When provided, routes in -return_nets are "
                             "added automatically via this gateway.")
    parser.add_argument("-return_nets", dest="return_nets",
                        default="10.0.0.0/8,172.16.0.0/30,192.168.1.0/24,192.168.2.0/24",
                        help="Comma-separated networks to route back via -gw. "
                             "Default covers the standard testbed topology: "
                             "10.0.0.0/8,172.16.0.0/30,192.168.1.0/24,192.168.2.0/24")

    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    flag = False
    interface_list = netifaces.interfaces()

    if args.if_server not in interface_list:
        print("Server interface invalid!")
        flag = True

    if not is_valid_ipv4_network(args.server_net):
        print("Server network invalid!")
        flag = True

    if flag:
        sys.exit(1)

    return (args.if_server, args.server_net, args.server_ip,
            args.web_port, args.gateway, args.return_nets)


def check_and_enable_interface(interface, ip_address):
    """
    Flushes existing IPs, assigns ip_address/24 to the interface,
    and brings it up.
    """
    try:
        subprocess.run(["ip", "addr", "flush", "dev", interface],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "addr", "add", f"{ip_address}/24", "dev", interface],
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        result = subprocess.run(["ip", "link", "show", interface],
                               capture_output=True, text=True, check=True)
        if "state UP" not in result.stdout:
            subprocess.run(["ip", "link", "set", "dev", interface, "up"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            print(f"Interface {interface} brought up with {ip_address}.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def add_return_routes(interface, gateway, return_nets):
    """
    Adds return routes to B4 LAN networks via the Server-Router gateway.
    Without these routes, the server cannot send reply packets back to
    B4 clients because it doesn't know how to reach 192.168.x.x networks.

    interface   -- server's own network interface (e.g. ens3)
    gateway     -- Server-Router's IP on the server LAN (e.g. 10.1.0.254)
    return_nets -- comma-separated list of networks to route
    """
    for net in return_nets.split(','):
        net = net.strip()
        if not net:
            continue
        try:
            subprocess.run(["ip", "route", "add", net, "via", gateway, "dev", interface],
                          check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Return route {net} via {gateway} added.")
        except subprocess.CalledProcessError as e:
            print(f"Route {net} error (may already exist): {e}")


def start_web_server(ip_address, port):
    """
    Starts Python's built-in HTTP server serving /tmp on the given port.
    Creates a simple index.html with a timestamp so connectivity tests
    can confirm the correct host is responding.

    Test from a B4 client after full setup:
      curl http://10.1.0.1/     (or wget, or ping 10.1.0.1)
    """
    print(f"Starting web server on port {port}...")

    html_content = """<!DOCTYPE html>
<html>
<head><title>DS-Lite Test Server</title></head>
<body>
<h1>DS-Lite Testbed Server</h1>
<p>This server is accessible via DS-Lite tunnel.</p>
<p>Server time: """ + subprocess.getoutput("date") + """</p>
</body>
</html>
"""

    with open("/tmp/index.html", "w") as f:
        f.write(html_content)

    subprocess.Popen(
        ["python3", "-m", "http.server", str(port)],
        cwd="/tmp",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    print(f"Web server started on http://{ip_address}:{port}")


# -- Main ---------------------------------------------------------------------
try:
    if_server, server_net, server_ip, web_port, gateway, return_nets = parameter()

    if_server_global = if_server

    signal.signal(signal.SIGINT, signal_handler)

    print("\n" + "="*60)
    print("   DS-Lite Test Server")
    print("="*60)
    print(f"Interface: {if_server}")
    print(f"IP Address: {server_ip}")
    print(f"Network: {server_net}")
    print(f"Web Port: {web_port}")
    if gateway:
        print(f"Gateway: {gateway}")
        print(f"Return routes: {return_nets}")
    print("="*60 + "\n")

    # Assign IP and bring up the interface
    check_and_enable_interface(if_server, server_ip)

    # Add return routes to B4 LANs via Server-Router
    if gateway:
        add_return_routes(if_server, gateway, return_nets)

    # Start the HTTP test server
    start_web_server(server_ip, web_port)

    print("\n" + "="*60)
    print("   Server Running")
    print("="*60)
    print(f"Accessible at: http://{server_ip}:{web_port}")
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
