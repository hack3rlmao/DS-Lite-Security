# DS-Lite Testbed

A fully automated DS-Lite ([RFC 6333](https://datatracker.ietf.org/doc/html/rfc6333) / [RFC 6334](https://datatracker.ietf.org/doc/html/rfc6334)) testbed implemented in Python, designed to run on Linux virtual machines in GNS3 or any comparable emulation environment.

The testbed demonstrates the complete DS-Lite traffic flow: IPv4-in-IPv6 encapsulation at the B4 element, per-B4 tunnel termination and NAT44 at the AFTR, and end-to-end IPv4 connectivity between private LAN clients and a public server — all over an IPv6-only core network.

---

## Table of Contents

- [Architecture](#architecture)
- [Address Plan](#address-plan)
- [Requirements](#requirements)
- [Scripts](#scripts)
  - [kea_dhcpv6.py](#kea_dhcpv6py)
  - [b4.py](#b4py)
  - [aftr.py](#aftrpy)
  - [server_router.py](#server_routerpy)
  - [server.py](#serverpy)
- [Startup Order](#startup-order)
- [Quick Start](#quick-start)
- [DNS Records](#dns-records)
- [Known Limitations](#known-limitations)

---

## Architecture

```
PC1 ──► Switch1 ──► B4-1 ──┐
                            │  IPv6 CORE (2001:db8::/64)
PC2 ──► Switch2 ──► B4-2 ──┤
                            │
                     DHCPv6-DNS
                            │
                          AFTR
                            │  172.16.0.0/30
                    SERVER-ROUTER
                            │  10.1.0.0/16
                          Server
```

### Traffic flow

```
PC1 (192.168.1.x)
  │  IPv4
  ▼
B4-1                     [encapsulates IPv4 in IPv6 → ip6tnl tunnel]
  │  IPv6 (outer) / IPv4 (inner)
  ▼
AFTR                     [decapsulates → NAT44 → forwards to server]
  │  IPv4 (NATed)
  ▼
Server-Router            [pure L3 routing, no NAT]
  │
  ▼
Server (10.1.0.1)
```

---

## Address Plan

| Node | Interface | Address |
|------|-----------|---------|
| DHCPv6-DNS | ens3 | `2001:db8::1/64` |
| AFTR | ens3 (CORE) | `2001:db8::10/64` |
| AFTR | ens4 (WAN) | `172.16.0.1/30` |
| B4-1 | ens3 (LAN) | `192.168.1.1/24` |
| B4-1 | ens4 (CORE) | `2001:db8::b1/64` (DHCPv6 reservation) |
| B4-2 | ens3 (LAN) | `192.168.2.1/24` |
| B4-2 | ens4 (CORE) | `2001:db8::b2/64` (DHCPv6 reservation) |
| Server-Router | ens3 (AFTR-side) | `172.16.0.2/30` |
| Server-Router | ens4 (Server-side) | `10.1.0.254/16` |
| Server | ens3 | `10.1.0.1/24` |

---

## Requirements

Each node must have:

- Ubuntu 22.04 or compatible Linux distribution
- Python 3.8+
- `netifaces` Python package: `pip3 install netifaces`

Additional per-node requirements:

| Node | Package |
|------|---------|
| DHCPv6-DNS | `kea` (`apt install kea`), `dnsmasq` |
| B4 | `isc-dhcp-client` (`dhclient`), `dnsmasq`, `iproute2` |
| AFTR | `iptables`, `iproute2` |
| Server | `python3` (built-in HTTP server) |

---

## Scripts

---

### `kea_dhcpv6.py`

Runs on the **DHCPv6-DNS** node. Assigns IPv6 addresses and DHCPv6 option 64 (AFTR-Name, RFC 6334) to B4 nodes. Also starts a `dnsmasq` DNS forwarder with static records for AFTR and B4 nodes so clients can resolve FQDNs locally.

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-i` | **Yes** | — | Network interface on the IPv6 CORE network (e.g. `ens3`). |
| `-p` | **Yes** | — | IPv6 prefix to serve (e.g. `2001:db8::/64`). The server takes `.1`, the pool starts at offset `-start`. |
| `-aftr` | **Yes** | — | AFTR FQDN sent in DHCPv6 option 64 (e.g. `aftr.dslite.local`). B4 nodes resolve this name to reach the AFTR tunnel endpoint. |
| `-aftr_ip` | No | — | AFTR IPv6 address. Added as a static DNS `AAAA` record in dnsmasq so B4 nodes can resolve the AFTR FQDN locally (e.g. `2001:db8::10`). Required for DNS-based AFTR resolution to work correctly. |
| `-reservations` | No | — | Static DHCPv6 leases as `MAC=IPv6` pairs, comma-separated. Ensures each B4 always receives the same IPv6 address after every restart. Example: `0c:ca:02:e7:00:01=2001:db8::b1,0c:a0:a9:03:00:01=2001:db8::b2`. Get MAC addresses with `ip link show ens4` on each B4 node. |
| `-b4_dns` | No | — | Static DNS `A`/`AAAA` records, as `FQDN=IP` pairs, comma-separated. Adds records to dnsmasq for any host in the testbed. Example: `b4-1.dslite.local=2001:db8::b1,server.dslite.local=10.1.0.1`. |
| `-dns` | No | Google DNS | Upstream DNS servers to forward external queries to, comma-separated. |
| `-dom` | No | `dslite.local` | DNS search domain sent to clients. |
| `-lease` | No | `1h` | DHCPv6 lease time. Accepts `Nh` (hours), `Nm` (minutes), `Ns` (seconds). |
| `-start` | No | `100` | Pool start offset from the network base address. Default → `2001:db8::64`. |
| `-end` | No | `200` | Pool end offset from the network base address. Default → `2001:db8::c8`. |
| `-no-dns` | No | `false` | Flag. Disables the built-in dnsmasq DNS forwarder. |

#### Example

```bash
sudo python3 kea_dhcpv6.py \
  -i ens3 \
  -p 2001:db8::/64 \
  -aftr aftr.dslite.local \
  -aftr_ip 2001:db8::10 \
  -reservations 0c:ca:02:e7:00:01=2001:db8::b1,0c:a0:a9:03:00:01=2001:db8::b2 \
  -b4_dns b4-1.dslite.local=2001:db8::b1,b4-2.dslite.local=2001:db8::b2,server.dslite.local=10.1.0.1
```

#### Expected output

```
Reservation: 0c:ca:02:e7:00:01 -> 2001:db8::b1
Reservation: 0c:a0:a9:03:00:01 -> 2001:db8::b2
Interface ens3 configured with 2001:db8::1/64
DNS record added: aftr.dslite.local -> 2001:db8::10
DNS record added: b4-1.dslite.local -> 2001:db8::b1
DNS record added: b4-2.dslite.local -> 2001:db8::b2
DNS record added: server.dslite.local -> 10.1.0.1
DNS forwarder started successfully.
KEA DHCPv6 server started successfully.
SERVER RUNNING
```

---

### `b4.py`

Runs on each **B4** node. Obtains an IPv6 address and AFTR FQDN via DHCPv6, resolves the AFTR address via DNS, and creates a DS-Lite `ip6tnl` tunnel (`mode ipip6`). Optionally serves DHCPv4 to local LAN clients via `dnsmasq`.

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-ic` | **Yes** | — | Client (LAN) interface connected to local PCs (e.g. `ens3`). |
| `-it` | **Yes** | — | Tunnel (WAN/CORE) interface connected to the IPv6 CORE network (e.g. `ens4`). DHCPv6 runs on this interface. |
| `-lan_ip` | No | — | IPv4 address to assign to the LAN interface (e.g. `192.168.1.1/24`). If omitted, the address must be set manually before running. |
| `-net` | No | — | IPv4 network reachable via the DS-Lite tunnel (e.g. `10.0.0.0/8`). A route to this network is added via the tunnel interface. |
| `-cross_routes` | No | — | Comma-separated IPv4 networks of other B4 LANs to route via the tunnel (e.g. `192.168.2.0/24`). Enables inter-B4 communication through the AFTR. |
| `-tn` | No | `ipip6` | Name for the `ip6tnl` tunnel interface. Use a unique name per B4 node (e.g. `ipip6_b4_1`). |
| `-mtu` | No | `1452` | Tunnel MTU. Default accounts for 40-byte IPv6 header on a 1500-byte Ethernet link. |
| `-dhcp` | No | — | DHCPv4 address range for LAN clients (e.g. `192.168.1.100-192.168.1.200`). Requires an IPv4 address on the LAN interface (via `-lan_ip` or manually). |
| `-dns` | No | LAN gateway | DNS server IP handed out to DHCPv4 clients. Defaults to the LAN interface gateway. |
| `-lease` | No | `1h` | DHCPv4 lease time (e.g. `1h`, `30m`). |
| `-dhcpv6-timeout` | No | `15` | Seconds to wait for a DHCPv6 reply before giving up. |

#### Example — B4-1

```bash
sudo python3 b4.py \
  -ic ens3 \
  -it ens4 \
  -lan_ip 192.168.1.1/24 \
  -net 10.0.0.0/8 \
  -dhcp 192.168.1.100-192.168.1.200 \
  -cross_routes 192.168.2.0/24 \
  -tn ipip6_b4_1
```

#### Expected output

```
B4 Configuration Complete
B4 IPv6:   2001:db8::b1
AFTR IPv6: 2001:db8::10
Tunnel:    ipip6_b4_1
DHCPv4:    192.168.1.100-192.168.1.200
Cross-B4:  192.168.2.0/24
```

---

### `aftr.py`

Runs on the **AFTR** node. Creates one dedicated `ip6tnl` tunnel per known B4 node (per-B4 model), performs NAT44 via `iptables MASQUERADE`, and routes decapsulated IPv4 traffic to the server network. Must be started **after** all B4 nodes have obtained their IPv6 addresses.

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-it` | **Yes** | — | CORE-side interface towards B4 nodes over IPv6 (e.g. `ens3`). |
| `-is` | **Yes** | — | Server-side interface towards the IPv4 network / server-router (e.g. `ens4`). |
| `-aftr` | No | auto-detect | AFTR's own IPv6 address on the CORE interface (e.g. `2001:db8::10`). Assigned to the `-it` interface automatically. If omitted, the existing non-link-local address on the interface is used. |
| `-b4nets` | No | — | Per-B4 mapping as `B4_IPv6:LAN_network` pairs, comma-separated. One dedicated tunnel is created per entry. Example: `2001:db8::b1:192.168.1.0/24,2001:db8::b2:192.168.2.0/24`. |
| `-aftr_ip4` | No | — | IPv4 address to assign to the server-side interface (e.g. `172.16.0.1/30`). Assigned automatically at startup. |
| `-gw_ip4` | No | — | IPv4 gateway on the server side (e.g. `172.16.0.2`). Used together with `-server_net` to add a route to the server network. |
| `-server_net` | No | — | IPv4 network of the server side (e.g. `10.1.0.0/16`). A route to this network via `-gw_ip4` is added automatically. |
| `-tn` | No | `ipip6` | Base name for tunnel interfaces. Tunnels are named `<base>_1`, `<base>_2`, etc. |
| `-mtu` | No | `1452` | Tunnel MTU. |
| `-net` | No | — | **(Legacy)** Single client network for a dynamic `remote any` tunnel. Use `-b4nets` instead. |

#### Example

```bash
sudo python3 aftr.py \
  -it ens3 \
  -is ens4 \
  -aftr 2001:db8::10 \
  -b4nets 2001:db8::b1:192.168.1.0/24,2001:db8::b2:192.168.2.0/24 \
  -aftr_ip4 172.16.0.1/30 \
  -gw_ip4 172.16.0.2 \
  -server_net 10.1.0.0/16
```

#### Expected output

```
AFTR IPv6 2001:db8::10/64 assigned to ens3.
IP 172.16.0.1/30 assigned to ens4.
Per-B4 tunnel 'ipip6_1' created (remote: 2001:db8::b1)
Per-B4 tunnel 'ipip6_2' created (remote: 2001:db8::b2)
Traffic forwarding enabled.
AFTR Configuration Complete
```

---

### `server_router.py`

Runs on the **Server-Router** node. Acts as a pure IPv4 L3 router between the AFTR and the server — no NAT is performed here. Enables IP forwarding and optionally assigns IP addresses and return routes.

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-ia` | **Yes** | — | Interface facing the AFTR node (e.g. `ens3`). |
| `-is` | **Yes** | — | Interface facing the Server node (e.g. `ens4`). |
| `-ia_ip` | No | — | IPv4 address to assign to the AFTR-facing interface (e.g. `172.16.0.2/30`). Assigned automatically at startup. |
| `-is_ip` | No | — | IPv4 address to assign to the Server-facing interface (e.g. `10.1.0.254/16`). Assigned automatically at startup. |
| `-client_gw` | No | — | IPv4 gateway on the AFTR side for return routes to B4 LANs (e.g. `172.16.0.1`). Used together with `-client_net`. |
| `-client_net` | No | `192.168.0.0/16` | IPv4 network of B4 clients. A return route via `-client_gw` is added for this network. |
| `-aftr_net` | No | `10.0.0.0/8` | IPv4 network on the AFTR side (informational). |
| `-server_net` | No | `10.1.0.0/16` | IPv4 network on the Server side (informational). |

#### Example

```bash
sudo python3 server_router.py \
  -ia ens3 \
  -is ens4 \
  -ia_ip 172.16.0.2/30 \
  -is_ip 10.1.0.254/16 \
  -client_gw 172.16.0.1 \
  -client_net 192.168.0.0/16
```

#### Expected output

```
IP 172.16.0.2/30 assigned to ens3.
IP 10.1.0.254/16 assigned to ens4.
Return route 192.168.0.0/16 via 172.16.0.1 added.
Traffic forwarding enabled.
Server-Router Running
```

---

### `server.py`

Runs on the **Server** node. Assigns an IPv4 address to its interface, adds return routes to B4 LAN networks via the Server-Router, and starts a minimal HTTP server to verify end-to-end connectivity.

#### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-i` | **Yes** | — | Network interface connected to the server network (e.g. `ens3`). |
| `-ip` | No | `10.0.0.1` | IPv4 address to assign to the interface. |
| `-gw` | No | — | IPv4 gateway (Server-Router) for adding return routes to B4 LANs (e.g. `10.1.0.254`). When provided, routes in `-return_nets` are added via this gateway. |
| `-return_nets` | No | `10.0.0.0/8,`<br>`172.16.0.0/30,`<br>`192.168.1.0/24,`<br>`192.168.2.0/24` | Comma-separated networks to route back via `-gw`. Default covers the standard testbed topology. |
| `-net` | No | `10.1.0.0/16` | Server network IPv4 range (informational). |
| `-web` | No | `80` | Port for the HTTP test server. Test with `curl http://<server_ip>/`. |

#### Example

```bash
sudo python3 server.py \
  -i ens3 \
  -ip 10.1.0.1 \
  -gw 10.1.0.254
```

#### Expected output

```
Return route 10.0.0.0/8 via 10.1.0.254 added.
Return route 172.16.0.0/30 via 10.1.0.254 added.
Return route 192.168.1.0/24 via 10.1.0.254 added.
Return route 192.168.2.0/24 via 10.1.0.254 added.
Web server started on http://10.1.0.1:80
Server Running
```

---

## Startup Order

The nodes must be started in the following order. Each script blocks (runs until Ctrl+C), so use a separate terminal session per node.

```
1. DHCPv6-DNS   kea_dhcpv6.py   Must be running before B4 nodes start
2. Server-Router server_router.py
3. Server        server.py
4. B4-1          b4.py          Obtains IPv6 from DHCPv6 (step 1)
5. B4-2          b4.py
6. AFTR          aftr.py        Must be started after B4 nodes (needs their IPv6 addresses)
```

> **Why AFTR is last:** The AFTR creates a dedicated tunnel per B4 node using that node's current IPv6 address. The address must be known and stable before the tunnel is created. With KEA static reservations (`-reservations`), B4 nodes always receive the same IPv6 after every restart, so the AFTR command never changes.

---

## Quick Start

Full startup sequence for the default topology.

### Step 1 — DHCPv6-DNS (`192.168.122.13`)

```bash
sudo python3 kea_dhcpv6.py \
  -i ens3 -p 2001:db8::/64 \
  -aftr aftr.dslite.local -aftr_ip 2001:db8::10 \
  -reservations 0c:ca:02:e7:00:01=2001:db8::b1,0c:a0:a9:03:00:01=2001:db8::b2 \
  -b4_dns b4-1.dslite.local=2001:db8::b1,b4-2.dslite.local=2001:db8::b2,server.dslite.local=10.1.0.1
```

### Step 2 — Server-Router (`192.168.122.14`)

```bash
sudo python3 server_router.py \
  -ia ens3 -is ens4 \
  -ia_ip 172.16.0.2/30 -is_ip 10.1.0.254/16 \
  -client_gw 172.16.0.1 -client_net 192.168.0.0/16
```

### Step 3 — Server (`192.168.122.15`)

```bash
sudo python3 server.py \
  -i ens3 -ip 10.1.0.1 -gw 10.1.0.254
```

### Step 4 — B4-1 (`192.168.122.11`)

```bash
sudo python3 b4.py \
  -ic ens3 -it ens4 \
  -lan_ip 192.168.1.1/24 \
  -net 10.0.0.0/8 \
  -dhcp 192.168.1.100-192.168.1.200 \
  -cross_routes 192.168.2.0/24 \
  -tn ipip6_b4_1
```

### Step 5 — B4-2 (`192.168.122.12`)

```bash
sudo python3 b4.py \
  -ic ens3 -it ens4 \
  -lan_ip 192.168.2.1/24 \
  -net 10.0.0.0/8 \
  -dhcp 192.168.2.100-192.168.2.200 \
  -cross_routes 192.168.1.0/24 \
  -tn ipip6_b4_2
```

### Step 6 — AFTR (`192.168.122.10`)

```bash
sudo python3 aftr.py \
  -it ens3 -is ens4 \
  -aftr 2001:db8::10 \
  -b4nets 2001:db8::b1:192.168.1.0/24,2001:db8::b2:192.168.2.0/24 \
  -aftr_ip4 172.16.0.1/30 \
  -gw_ip4 172.16.0.2 \
  -server_net 10.1.0.0/16
```

### Step 7 — Verify

All paths should show 0% packet loss:

```bash
# From B4-1:
ping -c 4 10.1.0.1         # B4-1 → Server
ping -c 4 192.168.2.1      # B4-1 → B4-2 LAN

# From B4-2:
ping -c 4 10.1.0.1         # B4-2 → Server
ping -c 4 192.168.1.1      # B4-2 → B4-1 LAN

# From Server:
ping -c 4 192.168.1.1      # Server → B4-1 LAN
ping -c 4 192.168.2.1      # Server → B4-2 LAN
```

LAN client test (on PC1 / PC2 in GNS3):

```
ip dhcp
ping 10.1.0.1
ping server.dslite.local
```

---

## DNS Records

The following DNS records are configured by the example command above and are resolvable from any node in the testbed:

| Name | Type | Value |
|------|------|-------|
| `aftr.dslite.local` | AAAA | `2001:db8::10` |
| `b4-1.dslite.local` | AAAA | `2001:db8::b1` |
| `b4-2.dslite.local` | AAAA | `2001:db8::b2` |
| `server.dslite.local` | A | `10.1.0.1` |

> **Note:** PC1 and PC2 cannot resolve `aftr.dslite.local` — this is expected. AFTR has an IPv6-only CORE address; PCs are IPv4-only clients and have no IPv6 connectivity. The AFTR is transparent to them by design.

---
