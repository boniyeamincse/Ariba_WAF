#!/usr/bin/env python3
"""
Ariba WAF IP Filter Module - Basic Version
"""

import ipaddress
import logging
from typing import Dict, Any, Optional, Tuple, Set, Union
from enum import Enum

class IPFilterAction(Enum):
    """IP Filter actions"""
    ALLOW = "allow"
    BLOCK = "block"
    CHALLENGE = "challenge"

class IPFilter:
    """Basic IP Filter for Ariba WAF"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize IP Filter"""
        self.default_config = {
            'whitelist': [],
            'blacklist': [],
            'default_action': IPFilterAction.ALLOW.value,
        }
        self.config = {**self.default_config, **(config or {})}
        self.whitelist: Set[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = set()
        self.blacklist: Set[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = set()
        self._load_ip_lists()

    def _load_ip_lists(self):
        """Load IP lists from configuration"""
        for ip_entry in self.config.get('whitelist', []):
            self._add_to_list(ip_entry, self.whitelist)
        for ip_entry in self.config.get('blacklist', []):
            self._add_to_list(ip_entry, self.blacklist)

    def _add_to_list(self, ip_entry: str, ip_set: Set):
        """Add IP entry to set"""
        try:
            if '/' in ip_entry:
                ip_net = ipaddress.ip_network(ip_entry, strict=False)
            else:
                ip_addr = ipaddress.ip_address(ip_entry)
                if isinstance(ip_addr, ipaddress.IPv4Address):
                    ip_net = ipaddress.IPv4Network(f"{ip_entry}/32", strict=False)
                else:
                    ip_net = ipaddress.IPv6Network(f"{ip_entry}/128", strict=False)
            ip_set.add(ip_net)
        except ValueError:
            pass  # Skip invalid entries

    def _is_ip_in_networks(self, ip_str: str, networks: Set) -> bool:
        """Check if IP is in any network"""
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            return any(ip_addr in network for network in networks)
        except ValueError:
            return False

    def check_ip(self, ip_address: str) -> Tuple[IPFilterAction, str]:
        """Check IP against filter rules"""
        if not ip_address:
            return IPFilterAction(self.config['default_action']), "Invalid IP"

        if self._is_ip_in_networks(ip_address, self.whitelist):
            return IPFilterAction.ALLOW, "Whitelisted"

        if self._is_ip_in_networks(ip_address, self.blacklist):
            return IPFilterAction.BLOCK, "Blacklisted"

        return IPFilterAction(self.config['default_action']), "Default action"

# Test
if __name__ == "__main__":
    config = {
        'whitelist': ['192.168.1.0/24', '10.0.0.1'],
        'blacklist': ['192.168.2.0/24', '10.0.0.5'],
        'default_action': 'allow'
    }

    ip_filter = IPFilter(config)

    test_ips = [
        '192.168.1.10',  # whitelisted
        '192.168.2.10',  # blacklisted
        '8.8.8.8',       # default action
    ]

    for ip in test_ips:
        action, reason = ip_filter.check_ip(ip)
        print(f"{ip}: {action.value} ({reason})")
