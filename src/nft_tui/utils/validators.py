"""Input validation utilities."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..nft.client import NFTClient


@dataclass
class ValidationResult:
    """Result of a validation check."""

    valid: bool
    error: str = ""


class RuleValidator:
    """Validator for nftables rules and inputs."""

    # Valid address families
    VALID_FAMILIES = {"ip", "ip6", "inet", "arp", "bridge", "netdev"}

    # Valid chain types
    VALID_CHAIN_TYPES = {"filter", "nat", "route"}

    # Valid hooks per family
    VALID_HOOKS = {
        "ip": {"prerouting", "input", "forward", "output", "postrouting"},
        "ip6": {"prerouting", "input", "forward", "output", "postrouting"},
        "inet": {"prerouting", "input", "forward", "output", "postrouting"},
        "arp": {"input", "output"},
        "bridge": {"prerouting", "input", "forward", "output", "postrouting"},
        "netdev": {"ingress", "egress"},
    }

    # Valid chain policies
    VALID_POLICIES = {"accept", "drop"}

    # Identifier pattern (for table/chain/set names)
    IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_-]*$")

    # Common protocol keywords
    VALID_PROTOCOLS = {
        "tcp",
        "udp",
        "icmp",
        "icmpv6",
        "sctp",
        "dccp",
        "udplite",
        "esp",
        "ah",
        "comp",
        "gre",
        "ipip",
    }

    # Common port names
    WELL_KNOWN_PORTS = {
        "ssh": 22,
        "http": 80,
        "https": 443,
        "dns": 53,
        "smtp": 25,
        "ftp": 21,
        "telnet": 23,
        "ntp": 123,
    }

    def __init__(self, client: NFTClient | None = None):
        """Initialize validator with optional NFT client for live validation."""
        self.client = client

    def validate_family(self, family: str) -> ValidationResult:
        """Validate an address family."""
        if family.lower() in self.VALID_FAMILIES:
            return ValidationResult(True)
        return ValidationResult(
            False, f"Invalid family '{family}'. Must be one of: {', '.join(self.VALID_FAMILIES)}"
        )

    def validate_identifier(self, name: str, entity: str = "name") -> ValidationResult:
        """Validate a table/chain/set identifier name."""
        if not name:
            return ValidationResult(False, f"{entity.capitalize()} cannot be empty")

        if len(name) > 64:
            return ValidationResult(False, f"{entity.capitalize()} must be 64 characters or less")

        if not self.IDENTIFIER_PATTERN.match(name):
            return ValidationResult(
                False,
                f"{entity.capitalize()} must start with a letter or underscore "
                "and contain only letters, numbers, underscores, or hyphens",
            )

        return ValidationResult(True)

    def validate_table_name(self, name: str) -> ValidationResult:
        """Validate a table name."""
        return self.validate_identifier(name, "table name")

    def validate_chain_name(self, name: str) -> ValidationResult:
        """Validate a chain name."""
        return self.validate_identifier(name, "chain name")

    def validate_set_name(self, name: str) -> ValidationResult:
        """Validate a set name."""
        return self.validate_identifier(name, "set name")

    def validate_chain_type(self, chain_type: str) -> ValidationResult:
        """Validate a chain type."""
        if chain_type.lower() in self.VALID_CHAIN_TYPES:
            return ValidationResult(True)
        return ValidationResult(
            False,
            f"Invalid chain type '{chain_type}'. "
            f"Must be one of: {', '.join(self.VALID_CHAIN_TYPES)}",
        )

    def validate_hook(self, hook: str, family: str) -> ValidationResult:
        """Validate a chain hook for the given family."""
        valid_hooks = self.VALID_HOOKS.get(family.lower(), set())
        if hook.lower() in valid_hooks:
            return ValidationResult(True)
        return ValidationResult(
            False,
            f"Invalid hook '{hook}' for family '{family}'. "
            f"Must be one of: {', '.join(valid_hooks)}",
        )

    def validate_priority(self, priority: int | str) -> ValidationResult:
        """Validate a chain priority."""
        try:
            prio = int(priority)
            if -2147483648 <= prio <= 2147483647:
                return ValidationResult(True)
            return ValidationResult(False, "Priority must be a 32-bit signed integer")
        except (ValueError, TypeError):
            return ValidationResult(False, "Priority must be an integer")

    def validate_policy(self, policy: str) -> ValidationResult:
        """Validate a chain policy."""
        if policy.lower() in self.VALID_POLICIES:
            return ValidationResult(True)
        return ValidationResult(
            False,
            f"Invalid policy '{policy}'. Must be one of: {', '.join(self.VALID_POLICIES)}",
        )

    def validate_ip_address(self, addr: str) -> ValidationResult:
        """Validate an IP address (v4 or v6)."""
        try:
            ipaddress.ip_address(addr)
            return ValidationResult(True)
        except ValueError:
            return ValidationResult(False, f"Invalid IP address: {addr}")

    def validate_ip_network(self, network: str) -> ValidationResult:
        """Validate an IP network/CIDR."""
        try:
            ipaddress.ip_network(network, strict=False)
            return ValidationResult(True)
        except ValueError:
            return ValidationResult(False, f"Invalid IP network: {network}")

    def validate_port(self, port: int | str) -> ValidationResult:
        """Validate a port number."""
        try:
            port_num = int(port)
            if 0 <= port_num <= 65535:
                return ValidationResult(True)
            return ValidationResult(False, "Port must be between 0 and 65535")
        except (ValueError, TypeError):
            # Check if it's a well-known port name
            if str(port).lower() in self.WELL_KNOWN_PORTS:
                return ValidationResult(True)
            return ValidationResult(False, f"Invalid port: {port}")

    def validate_port_range(self, port_range: str) -> ValidationResult:
        """Validate a port range (e.g., '80-443')."""
        if "-" not in port_range:
            return self.validate_port(port_range)

        parts = port_range.split("-")
        if len(parts) != 2:
            return ValidationResult(False, "Port range must be in format 'start-end'")

        start_valid = self.validate_port(parts[0])
        if not start_valid.valid:
            return start_valid

        end_valid = self.validate_port(parts[1])
        if not end_valid.valid:
            return end_valid

        if int(parts[0]) > int(parts[1]):
            return ValidationResult(False, "Start port must be less than or equal to end port")

        return ValidationResult(True)

    def validate_interface(self, iface: str) -> ValidationResult:
        """Validate a network interface name."""
        if not iface:
            return ValidationResult(False, "Interface name cannot be empty")

        if len(iface) > 15:
            return ValidationResult(False, "Interface name must be 15 characters or less")

        if not re.match(r"^[a-zA-Z0-9_*-]+$", iface):
            return ValidationResult(
                False, "Interface name contains invalid characters"
            )

        return ValidationResult(True)

    def validate_mac_address(self, mac: str) -> ValidationResult:
        """Validate a MAC address."""
        mac_pattern = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
        if mac_pattern.match(mac):
            return ValidationResult(True)
        return ValidationResult(False, f"Invalid MAC address: {mac}")

    async def validate_rule_async(self, rule_spec: str) -> ValidationResult:
        """Validate a rule specification using nft -c.

        This requires the NFT client to be set.
        """
        if not self.client:
            return ValidationResult(False, "NFT client not available for validation")

        valid, error = await self.client.validate_async(rule_spec)
        if valid:
            return ValidationResult(True)
        return ValidationResult(False, error)

    def validate_rule(self, rule_spec: str) -> ValidationResult:
        """Validate a rule specification using nft -c."""
        if not self.client:
            return ValidationResult(False, "NFT client not available for validation")

        valid, error = self.client.validate(rule_spec)
        if valid:
            return ValidationResult(True)
        return ValidationResult(False, error)

    def validate_set_type(self, set_type: str) -> ValidationResult:
        """Validate a set type specification."""
        valid_types = {
            "ipv4_addr",
            "ipv6_addr",
            "ether_addr",
            "inet_proto",
            "inet_service",
            "mark",
            "ifname",
        }

        # Handle concatenated types like "ipv4_addr . inet_service"
        parts = [p.strip() for p in set_type.split(".")]

        for part in parts:
            if part not in valid_types:
                return ValidationResult(
                    False,
                    f"Invalid set type '{part}'. Valid types: {', '.join(valid_types)}",
                )

        return ValidationResult(True)

    def validate_chain_spec(
        self,
        family: str,
        table: str,
        name: str,
        chain_type: str | None = None,
        hook: str | None = None,
        priority: int | str | None = None,
        policy: str | None = None,
    ) -> ValidationResult:
        """Validate a complete chain specification."""
        # Validate family
        result = self.validate_family(family)
        if not result.valid:
            return result

        # Validate table name
        result = self.validate_table_name(table)
        if not result.valid:
            return result

        # Validate chain name
        result = self.validate_chain_name(name)
        if not result.valid:
            return result

        # If it's a base chain, validate type/hook/priority
        if chain_type or hook or priority is not None:
            if not all([chain_type, hook, priority is not None]):
                return ValidationResult(
                    False, "Base chains must specify type, hook, and priority"
                )

            result = self.validate_chain_type(chain_type)
            if not result.valid:
                return result

            result = self.validate_hook(hook, family)
            if not result.valid:
                return result

            result = self.validate_priority(priority)
            if not result.valid:
                return result

        # Validate policy if provided
        if policy:
            result = self.validate_policy(policy)
            if not result.valid:
                return result

        return ValidationResult(True)
