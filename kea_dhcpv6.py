#!/usr/bin/python3
"""
KEA DHCPv6 Server for DS-Lite CORE network.

Role in DS-Lite:
  This script runs on the DHCPv6-DNS node. When a B4 node boots and
  connects to the CORE IPv6 network, it sends a DHCPv6 Solicit. This
  server replies with:
    - A global IPv6 address from the configured pool (e.g. 2001:db8::64-c8)
    - Option 64 (AFTR-Name, RFC 6334): the FQDN of the AFTR node
    - DNS server addresses so B4 can resolve the AFTR FQDN to an IPv6 address

  It also starts a dnsmasq instance that acts as a local DNS resolver and
  answers queries for the AFTR FQDN -> AFTR IPv6 address mapping.

DS-Lite flow triggered by this script:
  B4 boots -> DHCPv6 Solicit -> [this script] -> Advertise with IPv6 + AFTR-Name
  B4 resolves AFTR-Name via DNS -> gets AFTR IPv6 -> creates ip6tnl tunnel
"""

import argparse
import subprocess
import sys
import signal
import os
import time
import json
import ipaddress

# -- Global state -------------------------------------------------------------
kea_process = None        # subprocess handle for kea-dhcp6
dns_process = None        # subprocess handle for dnsmasq
if_core_global = None     # CORE network interface name (for cleanup reference)
ipv6_prefix_global = None # IPv6 prefix being served (for cleanup reference)
config_file = "/tmp/kea_dhcpv6.json"   # KEA config written here at runtime

def signal_handler(sig, frame):
    print("\n---> Keyboard Interrupt received. Cleaning up...")
    cleanup()
    sys.exit(0)

def cleanup():
    """Stops KEA and dnsmasq, removes temporary files."""
    global kea_process, dns_process

    if kea_process:
        try:
            kea_process.terminate()
            kea_process.wait(timeout=5)
            print("KEA DHCPv6 server stopped.")
        except Exception as e:
            print(f"Warning: Could not stop KEA: {e}")
            try:
                kea_process.kill()
            except:
                pass

    if dns_process:
        try:
            dns_process.terminate()
            dns_process.wait(timeout=3)
            print("DNS server stopped.")
        except Exception as e:
            print(f"Warning: Could not stop DNS: {e}")
            try:
                dns_process.kill()
            except:
                pass

    # Remove temporary files created at startup
    for f in [config_file, "/tmp/kea_dhcpv6.pid", "/tmp/dnsmasq_dns.conf"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except:
                pass

    print("Cleanup completed.")


def parse_reservations(reservations_str):
    """
    Parses the -reservations argument into a list of (mac, ipv6) tuples.

    Format: "mac1=ipv6_1,mac2=ipv6_2"
    Example: "0c:ca:02:e7:00:01=2001:db8::b1,0c:a0:a9:03:00:01=2001:db8::b2"

    Uses '=' as delimiter to avoid ambiguity with colons in both MAC and IPv6.

    Returns list of {"hw-address": mac, "ip-addresses": [ipv6]} dicts
    suitable for insertion into the KEA subnet6 reservations list.
    """
    result = []
    if not reservations_str:
        return result
    for entry in reservations_str.split(','):
        entry = entry.strip()
        if '=' not in entry:
            print(f"Warning: skipping invalid reservation '{entry}' (expected mac=ipv6)")
            continue
        mac, ipv6 = entry.split('=', 1)
        mac  = mac.strip()
        ipv6 = ipv6.strip()
        result.append({"hw-address": mac, "ip-addresses": [ipv6]})
        print(f"Reservation: {mac} -> {ipv6}")
    return result


def parse_b4_dns(b4_dns_str):
    """
    Parses the -b4_dns argument into a list of (fqdn, ipv6) tuples.

    Format: "fqdn1=ipv6_1,fqdn2=ipv6_2"
    Example: "b4-1.dslite.local=2001:db8::b1,b4-2.dslite.local=2001:db8::b2"

    Returns list of (fqdn, ipv6) tuples used to build dnsmasq address= lines.
    """
    result = []
    if not b4_dns_str:
        return result
    for entry in b4_dns_str.split(','):
        entry = entry.strip()
        if '=' not in entry:
            print(f"Warning: skipping invalid b4_dns entry '{entry}' (expected fqdn=ipv6)")
            continue
        fqdn, ipv6 = entry.split('=', 1)
        result.append((fqdn.strip().rstrip('.'), ipv6.strip()))
    return result


def generate_kea_config(interface, ipv6_prefix, dns_servers, domain,
                        lease_time, aftr_name, start_offset=100, end_offset=200,
                        reservations=None):
    """
    Builds the KEA DHCPv6 JSON configuration dict.

    Pool addressing logic:
      network_address + start_offset  ->  pool start  (e.g. 2001:db8::64)
      network_address + end_offset    ->  pool end    (e.g. 2001:db8::c8)
      network_address + 1             ->  server addr (e.g. 2001:db8::1)

    Option 64 (AFTR-Name, RFC 6334):
      Encoded as a domain name in the DHCPv6 response. B4 elements parse
      this option, then resolve the FQDN via DNS to obtain the AFTR IPv6.

    reservations:
      List of {"hw-address": mac, "ip-addresses": [ipv6]} dicts.
      When provided, KEA always assigns the specified IPv6 to the B4 node
      with that MAC address -- address does not change after restarts.
      Reserved addresses are outside the dynamic pool to avoid conflicts.

    Returns:
      (config_dict, server_addr_string)
    """
    network = ipaddress.IPv6Network(ipv6_prefix, strict=False)
    server_addr = str(network.network_address + 1)      # .1 is the server itself
    pool_start  = str(network.network_address + start_offset)
    pool_end    = str(network.network_address + end_offset)

    # Build DNS list: local server first so B4 can hit it for AFTR FQDN resolution,
    # then Google IPv6 as fallback for actual internet DNS.
    dns_list = []
    if dns_servers:
        for dns in dns_servers.split(','):
            dns_list.append(dns.strip())
    else:
        dns_list = [server_addr, "2001:4860:4860::8888", "2001:4860:4860::8844"]

    # Convert human-readable lease time (e.g. "1h", "30m", "3600s") to seconds
    if 'h' in lease_time:
        lease_seconds = int(lease_time.rstrip('h')) * 3600
    elif 'm' in lease_time:
        lease_seconds = int(lease_time.rstrip('m')) * 60
    else:
        lease_seconds = int(lease_time.rstrip('s'))

    subnet6_entry = {
        "subnet": str(network),
        "pools": [
            {
                # Address pool for B4 nodes (offsets from network base)
                "pool": f"{pool_start} - {pool_end}"
            }
        ],
        "interface": interface,
        # Rapid-commit: 2-message exchange instead of 4 (faster assignment)
        "rapid-commit": True
    }

    # Add static reservations if provided.
    # KEA matches by hw-address (MAC) and always hands out the reserved IPv6,
    # regardless of what the dynamic pool would assign.
    if reservations:
        subnet6_entry["reservations"] = reservations

    config = {
        "Dhcp6": {
            # Bind KEA to the specified CORE interface only
            "interfaces-config": {
                "interfaces": [interface]
            },
            "preferred-lifetime": lease_seconds,
            "valid-lifetime": lease_seconds,
            # renew-timer: B4 asks to renew after this many seconds
            "renew-timer": 1000,
            # rebind-timer: B4 broadcasts rebind request if server doesn't respond
            "rebind-timer": 2000,
            # Global options sent to every B4 client
            "option-data": [
                {
                    "name": "dns-servers",
                    "data": ",".join(dns_list)
                },
                {
                    "name": "domain-search",
                    "data": domain
                },
                {
                    # Option 64 = AFTR-Name (RFC 6334)
                    # B4 nodes read this FQDN, resolve it to an IPv6 address,
                    # and use that address as the remote end of their ip6tnl tunnel.
                    "name": "aftr-name",
                    "code": 64,
                    "space": "dhcp6",
                    "data": aftr_name
                }
            ],
            "subnet6": [subnet6_entry],
            # Unix socket for kea-shell / management commands
            "control-socket": {
                "socket-type": "unix",
                "socket-name": "/tmp/kea_dhcpv6.sock"
            }
        }
    }

    return config, server_addr


def start_dns_server(interface, ipv6_prefix, upstream_dns, domain,
                     aftr_name=None, aftr_ipv6=None, b4_dns_records=None):
    """
    Starts dnsmasq as a lightweight DNS resolver on the CORE interface.

    Purpose:
      B4 nodes receive the AFTR FQDN via DHCPv6 option 64 but still need to
      resolve it to an IPv6 address. This dnsmasq instance answers that query
      with a static record: aftr_name -> aftr_ipv6.

      External queries (e.g. real internet hostnames) are forwarded to Google
      DNS (8.8.8.8 / 2001:4860:4860::8888).

    b4_dns_records:
      Optional list of (fqdn, ipv6) tuples for B4 nodes. Adds AAAA records
      so nodes can be referenced by name (e.g. b4-1.dslite.local).
    """
    global dns_process

    network = ipaddress.IPv6Network(ipv6_prefix, strict=False)
    server_addr = str(network.network_address + 1)

    # Build dnsmasq config file content
    dns_config = f"""interface={interface}
bind-interfaces
no-dhcp-interface={interface}
server=8.8.8.8
server=8.8.4.4
server=2001:4860:4860::8888
domain={domain}
expand-hosts
log-queries
"""
    # Add a static AAAA record so B4 nodes can resolve AFTR FQDN directly.
    # Without this record B4 would have to reach an external DNS which may
    # not be reachable before the tunnel is established -- chicken-and-egg problem.
    if aftr_name and aftr_ipv6:
        clean_name = aftr_name.rstrip('.')
        dns_config += f"address=/{clean_name}/{aftr_ipv6}\n"
        print(f"DNS record added: {clean_name} -> {aftr_ipv6}")

    # Add static AAAA records for B4 nodes (from -b4_dns parameter).
    # Useful for human-readable addressing and allows referring to B4 nodes
    # by name instead of raw IPv6 addresses.
    if b4_dns_records:
        for fqdn, ipv6 in b4_dns_records:
            dns_config += f"address=/{fqdn}/{ipv6}\n"
            print(f"DNS record added: {fqdn} -> {ipv6}")

    if upstream_dns:
        for dns in upstream_dns.split(','):
            dns_config += f"server={dns.strip()}\n"

    config_file = "/tmp/dnsmasq_dns.conf"
    with open(config_file, 'w') as f:
        f.write(dns_config)

    print(f"Starting DNS forwarder on {interface}...")

    cmd = ["dnsmasq", "-C", config_file, "--no-daemon"]

    try:
        dns_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)

        if dns_process.poll() is None:
            print("DNS forwarder started successfully.")
            return True
        else:
            stdout, stderr = dns_process.communicate()
            print(f"DNS forwarder failed: {stderr.decode()}")
            return False
    except FileNotFoundError:
        print("Warning: dnsmasq not found. DNS forwarding disabled.")
        return False
    except Exception as e:
        print(f"Error starting DNS: {e}")
        return False


def configure_interface(interface, ipv6_prefix):
    """
    Assigns the server IPv6 address (.1) to the CORE interface and enables
    IPv6 forwarding.

    IMPORTANT: Uses 'scope global' when flushing existing addresses.
    Without 'scope global' the flush would also remove the link-local (fe80::)
    address, which KEA needs as the source address for DHCPv6 Advertise/Reply
    messages (DHCPv6 uses link-local for on-link communication).
    Losing fe80:: causes KEA to silently ignore Solicit packets.
    """
    network = ipaddress.IPv6Network(ipv6_prefix, strict=False)
    server_addr = str(network.network_address + 1)

    try:
        # Remove only global-scope addresses (preserves link-local fe80::)
        subprocess.run(["ip", "-6", "addr", "flush", "dev", interface, "scope", "global"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Assign /64 server address
        subprocess.run(["ip", "-6", "addr", "add", f"{server_addr}/64", "dev", interface],
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", "dev", interface, "up"],
                      check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Enable IPv6 forwarding so KEA can forward multicast DHCPv6 traffic
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Accept router advertisements (needed in some topologies)
        subprocess.run(["sysctl", "-w", "net.ipv6.conf.all.accept_ra=2"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Wait for link-local (fe80::) to leave "tentative" state (DAD).
        # KEA binds to the fe80:: address on port 547. If it starts while the
        # address is still tentative, bind() fails with EADDRNOTAVAIL and KEA
        # reports "no sockets open" -- silently ignoring all DHCPv6 Solicits.
        print(f"Waiting for fe80:: on {interface} to stabilize...")
        for _ in range(20):
            result = subprocess.run(
                ["ip", "-6", "addr", "show", "dev", interface, "scope", "link"],
                capture_output=True, text=True
            )
            if "fe80:" in result.stdout and "tentative" not in result.stdout:
                break
            time.sleep(0.5)

        print(f"Interface {interface} configured with {server_addr}/64")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERROR configuring interface: {e}")
        return False


def check_interface_exists(interface):
    """Returns True if the named interface exists in the system."""
    try:
        subprocess.run(["ip", "link", "show", interface],
                      check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return True
    except subprocess.CalledProcessError:
        return False


def start_kea_dhcpv6(config_file):
    """
    Launches the kea-dhcp6 binary with the generated config file.

    /var/run/kea is on tmpfs and disappears after every reboot.
    KEA refuses to start if this directory is missing (it needs it for the
    PID file and logger_lockfile). We recreate it here before each start.
    """
    global kea_process

    print("Starting KEA DHCPv6 server...")

    # Try common install locations for the kea-dhcp6 binary
    kea_paths = ["/usr/sbin/kea-dhcp6", "/usr/bin/kea-dhcp6", "/usr/local/sbin/kea-dhcp6"]

    kea_binary = None
    for path in kea_paths:
        if os.path.exists(path):
            kea_binary = path
            break

    if not kea_binary:
        try:
            result = subprocess.run(["which", "kea-dhcp6"], capture_output=True, text=True)
            if result.returncode == 0:
                kea_binary = result.stdout.strip()
        except:
            pass

    if not kea_binary:
        print("ERROR: KEA DHCPv6 server not found! Install: apt install kea")
        return False

    # Recreate /var/run/kea which lives on tmpfs and is lost after reboot.
    # KEA writes its PID file and logger_lockfile here.
    os.makedirs("/var/run/kea", exist_ok=True)

    # Clear stale lease files so KEA re-evaluates reservations on fresh start.
    # Without this, KEA honors old dynamic leases from previous runs even when
    # a MAC now has a static reservation pointing to a different address.
    for lf in ["/var/lib/kea/kea-leases6.csv", "/var/lib/kea/kea-leases6.csv.2"]:
        try:
            if os.path.exists(lf):
                os.remove(lf)
        except Exception as e:
            print(f"Warning: could not clear lease file {lf}: {e}")

    # Run without -d (debug) flag to avoid flooding the log file.
    # We redirect stdout+stderr to a log file instead of PIPE -- using PIPE
    # without reading it causes the 64KB kernel buffer to fill up, which
    # blocks kea-dhcp6 from processing any packets (it hangs on write()).
    kea_log = "/tmp/kea_dhcpv6_run.log"
    cmd = [kea_binary, "-c", config_file]

    try:
        with open(kea_log, "w") as lf:
            kea_process = subprocess.Popen(cmd, stdout=lf, stderr=lf)
        time.sleep(3)   # Give KEA time to bind to the interface

        if kea_process.poll() is None:
            print("KEA DHCPv6 server started successfully.")
            return True
        else:
            print(f"KEA DHCPv6 server failed!")
            try:
                with open(kea_log) as lf:
                    print(lf.read()[-2000:])
            except:
                pass
            return False
    except Exception as e:
        print(f"ERROR starting KEA: {e}")
        return False


def parameter():
    """Parses and validates CLI arguments."""
    parser = argparse.ArgumentParser(
        description="KEA DHCPv6 Server for DS-Lite with AFTR-Name option (RFC 6334).")

    parser.add_argument("-i", dest="interface", required=True,
                        help="Network interface connected to the CORE IPv6 network (e.g. ens3).")
    parser.add_argument("-p", dest="ipv6_prefix", required=True,
                        help="IPv6 prefix to serve (e.g. 2001:db8::/64). "
                             "Server takes .1, pool starts at -start offset.")
    parser.add_argument("-aftr", dest="aftr_name", required=True,
                        help="AFTR FQDN sent in DHCPv6 option 64 (e.g. aftr.dslite.local). "
                             "B4 nodes resolve this name to reach the AFTR tunnel endpoint.")
    parser.add_argument("-dns", dest="dns_forward",
                        help="Comma-separated upstream DNS servers to forward external queries to. "
                             "Defaults to Google IPv6 DNS if omitted.")
    parser.add_argument("-dom", dest="domain", default="dslite.local",
                        help="DNS search domain sent to clients. Default: dslite.local")
    parser.add_argument("-lease", dest="lease_time", default="1h",
                        help="DHCPv6 lease time. Accepts 'Nh' (hours), 'Nm' (minutes), "
                             "'Ns' (seconds). Default: 1h")
    parser.add_argument("-start", dest="pool_start", type=int, default=100,
                        help="Pool start offset from network base address. Default: 100 (->  ::64)")
    parser.add_argument("-end", dest="pool_end", type=int, default=200,
                        help="Pool end offset from network base address. Default: 200 (-> ::c8)")
    parser.add_argument("-aftr_ip", dest="aftr_ip",
                        help="AFTR IPv6 address added as a static DNS record so B4 nodes can "
                             "resolve the AFTR FQDN locally (e.g. 2001:db8::10). "
                             "Required for DNS-based AFTR resolution to work.")
    parser.add_argument("-reservations", dest="reservations",
                        help="Static DHCPv6 leases: MAC=IPv6 pairs, comma-separated. "
                             "Ensures each B4 always gets the same IPv6 after every restart. "
                             "Example: 0c:ca:02:e7:00:01=2001:db8::b1,0c:a0:a9:03:00:01=2001:db8::b2 "
                             "Get MAC addresses with: ip link show ens4  (on each B4 node)")
    parser.add_argument("-b4_dns", dest="b4_dns",
                        help="Static DNS records for B4 nodes: FQDN=IPv6 pairs, comma-separated. "
                             "Adds AAAA records to dnsmasq so B4 nodes can be resolved by name. "
                             "Example: b4-1.dslite.local=2001:db8::b1,b4-2.dslite.local=2001:db8::b2")
    parser.add_argument("-no-dns", dest="no_dns", action="store_true",
                        help="Disable the built-in dnsmasq DNS forwarder.")

    args = parser.parse_args()

    flag = False

    if not check_interface_exists(args.interface):
        print(f"Interface {args.interface} does not exist!")
        flag = True

    try:
        ipaddress.IPv6Network(args.ipv6_prefix, strict=False)
    except:
        print("Invalid IPv6 prefix!")
        flag = True

    if '.' not in args.aftr_name:
        print("AFTR name must be valid FQDN!")
        flag = True

    if flag:
        sys.exit(1)

    return (args.interface, args.ipv6_prefix, args.aftr_name, args.dns_forward,
            args.domain, args.lease_time, args.pool_start, args.pool_end,
            args.no_dns, args.aftr_ip, args.reservations, args.b4_dns)


# -- Main ---------------------------------------------------------------------
try:
    (interface, ipv6_prefix, aftr_name, dns_forward, domain,
     lease_time, pool_start, pool_end, no_dns, aftr_ip,
     reservations_str, b4_dns_str) = parameter()

    if_core_global    = interface
    ipv6_prefix_global = ipv6_prefix

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Parse reservations and B4 DNS records early so we can show them in header
    reservations  = parse_reservations(reservations_str)
    b4_dns_records = parse_b4_dns(b4_dns_str)

    print("\n" + "="*60)
    print("   KEA DHCPv6 Server - DS-Lite CORE")
    print("="*60)
    print(f"Interface:    {interface}")
    print(f"IPv6 Prefix:  {ipv6_prefix}")
    print(f"AFTR-Name:    {aftr_name}")
    print(f"Domain:       {domain}")
    print(f"Pool:         .{pool_start} - .{pool_end}")
    if reservations:
        print(f"Reservations: {len(reservations)} static lease(s)")
    if b4_dns_records:
        print(f"B4 DNS:       {len(b4_dns_records)} record(s)")
    print("="*60 + "\n")

    # Step 1: Assign server IPv6 address to CORE interface
    if not configure_interface(interface, ipv6_prefix):
        cleanup()
        sys.exit(1)

    # Step 2: Generate KEA JSON config and write to /tmp
    kea_config, server_addr = generate_kea_config(
        interface, ipv6_prefix, dns_forward, domain,
        lease_time, aftr_name, pool_start, pool_end,
        reservations=reservations
    )

    with open(config_file, 'w') as f:
        json.dump(kea_config, f, indent=4)

    print(f"KEA config: {config_file}")
    print(f"Server IPv6: {server_addr}")

    # Step 3: Start DNS forwarder (unless -no-dns flag given)
    if not no_dns:
        start_dns_server(interface, ipv6_prefix, dns_forward, domain,
                         aftr_name, aftr_ip, b4_dns_records)

    # Step 4: Start KEA DHCPv6 daemon
    if not start_kea_dhcpv6(config_file):
        cleanup()
        sys.exit(1)

    print("\n" + "="*60)
    print("   SERVER RUNNING")
    print("="*60)
    print("Press Ctrl+C to stop.\n")

    # Main loop: watch for KEA crashes and exit if it dies
    while True:
        time.sleep(5)
        if kea_process and kea_process.poll() is not None:
            print("ERROR: KEA crashed!")
            cleanup()
            sys.exit(1)

except KeyboardInterrupt:
    cleanup()
    sys.exit(0)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    cleanup()
    sys.exit(1)
