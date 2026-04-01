#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Common validation functions for DS-Lite testbed.
"""

import subprocess
import sys
import random
import ipaddress
import netifaces

def get_ipv4_addresses(interface):
    """Returns a list of IPv4 addresses (with prefix) assigned to the interface."""
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True, text=True, check=True
        )
        addresses = []
        for line in result.stdout.splitlines():
            if "inet " in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    addresses.append(parts[1])
        return addresses if addresses else None
    except subprocess.CalledProcessError:
        return None

def get_ipv6_addresses(interface):
    """Returns a list of IPv6 addresses (with prefix) assigned to the interface."""
    try:
        result = subprocess.run(
            ["ip", "-6", "addr", "show", interface],
            capture_output=True, text=True, check=True
        )
        addresses = []
        for line in result.stdout.splitlines():
            if "inet6 " in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    addr = parts[1].split('%')[0]
                    addresses.append(addr)
        return addresses if addresses else None
    except subprocess.CalledProcessError:
        return None

def add_ipv6_address(interface, ipv6_addr):
    """Adds an IPv6 address to the interface. No-op if the address is already assigned."""
    try:
        current_addrs = get_ipv6_addresses(interface)
        if current_addrs and ipv6_addr in current_addrs:
            return True
        subprocess.run(
            ["ip", "-6", "addr", "add", ipv6_addr, "dev", interface],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error adding IPv6 address {ipv6_addr} to {interface}: {e}")
        return False

def is_valid_ipv4_network(network_str):
    """Returns True if the string is a valid IPv4 network in CIDR notation."""
    try:
        ipaddress.IPv4Network(network_str, strict=False)
        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False

def is_valid_ipv6(addr_str):
    """Returns True if the string is a valid IPv6 address (with or without prefix length)."""
    try:
        if '/' in addr_str:
            addr_str = addr_str.split('/')[0]
        ipaddress.IPv6Address(addr_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def is_valid_num(num_str):
    """Returns True if the string represents a positive integer."""
    try:
        val = int(num_str)
        return val > 0
    except ValueError:
        return False

def is_valid_ipv4_range(range_str):
    """Returns True if the string is a valid IPv4 DHCP range (start-end, start < end)."""
    try:
        if '-' not in range_str:
            return False
        start_ip, end_ip = range_str.split('-')
        start = ipaddress.IPv4Address(start_ip.strip())
        end = ipaddress.IPv4Address(end_ip.strip())
        return int(start) < int(end)
    except (ipaddress.AddressValueError, ValueError):
        return False

def is_valid_ipv6_prefix(prefix_str):
    """Returns True if the string is a valid IPv6 prefix in CIDR notation."""
    try:
        network = ipaddress.IPv6Network(prefix_str, strict=False)
        return network.prefixlen <= 128
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False

def is_valid_ipv4_addr(addr_str):
    """Returns True if the string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(addr_str)
        return True
    except:
        return False

def is_valid_fqdn(fqdn):
    """Returns True if the string is a valid FQDN (max 253 chars, labels max 63 chars)."""
    if not fqdn or len(fqdn) > 253:
        return False
    if '.' not in fqdn:
        return False
    labels = fqdn.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not label[0].isalnum() or not label[-1].isalnum():
            return False
    return True

def random_ipv6_addr(prefix_str):
    """Generates a random host IPv6 address within the given prefix."""
    try:
        network = ipaddress.IPv6Network(prefix_str, strict=False)
        prefix_len = network.prefixlen
        network_addr = int(network.network_address)
        host_bits = 128 - prefix_len
        max_host = (1 << host_bits) - 1
        random_suffix = random.randint(1, max_host - 1)
        final_addr_int = network_addr + random_suffix
        return str(ipaddress.IPv6Address(final_addr_int))
    except (ipaddress.AddressValueError, ValueError) as e:
        print(f"Error generating random IPv6 from prefix {prefix_str}: {e}")
        return "fe80::" + ':'.join(f'{random.randint(0, 65535):04x}' for _ in range(4))

def generate_tunnel_name(base_name, index):
    """Generates a unique tunnel interface name for a given B4 index."""
    return f"{base_name}_b4_{index}"

def get_interface_mac(interface):
    """Returns the MAC address of the given interface, or None if unavailable."""
    try:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_LINK in addrs:
            return addrs[netifaces.AF_LINK][0]['addr']
    except ValueError:
        pass
    return None