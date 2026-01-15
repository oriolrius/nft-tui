"""Tests for validators."""

import pytest

from nft_tui.utils.validators import RuleValidator


class TestRuleValidator:
    """Tests for RuleValidator class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.validator = RuleValidator()

    def test_validate_family_valid(self):
        """Test validating valid families."""
        for family in ["ip", "ip6", "inet", "arp", "bridge", "netdev"]:
            result = self.validator.validate_family(family)
            assert result.valid is True

    def test_validate_family_invalid(self):
        """Test validating invalid family."""
        result = self.validator.validate_family("invalid")
        assert result.valid is False
        assert "Invalid family" in result.error

    def test_validate_identifier_valid(self):
        """Test validating valid identifiers."""
        valid_names = ["filter", "my_table", "chain_1", "_private", "my-chain"]
        for name in valid_names:
            result = self.validator.validate_identifier(name)
            assert result.valid is True, f"'{name}' should be valid"

    def test_validate_identifier_empty(self):
        """Test validating empty identifier."""
        result = self.validator.validate_identifier("")
        assert result.valid is False
        assert "cannot be empty" in result.error

    def test_validate_identifier_too_long(self):
        """Test validating too long identifier."""
        result = self.validator.validate_identifier("a" * 65)
        assert result.valid is False
        assert "64 characters" in result.error

    def test_validate_identifier_invalid_chars(self):
        """Test validating identifier with invalid characters."""
        result = self.validator.validate_identifier("my table")
        assert result.valid is False

    def test_validate_identifier_starts_with_number(self):
        """Test validating identifier starting with number."""
        result = self.validator.validate_identifier("1table")
        assert result.valid is False

    def test_validate_chain_type_valid(self):
        """Test validating valid chain types."""
        for chain_type in ["filter", "nat", "route"]:
            result = self.validator.validate_chain_type(chain_type)
            assert result.valid is True

    def test_validate_chain_type_invalid(self):
        """Test validating invalid chain type."""
        result = self.validator.validate_chain_type("invalid")
        assert result.valid is False

    def test_validate_hook_valid(self):
        """Test validating valid hooks."""
        result = self.validator.validate_hook("input", "inet")
        assert result.valid is True

        result = self.validator.validate_hook("ingress", "netdev")
        assert result.valid is True

    def test_validate_hook_invalid(self):
        """Test validating invalid hook for family."""
        result = self.validator.validate_hook("ingress", "inet")
        assert result.valid is False

    def test_validate_priority_valid(self):
        """Test validating valid priorities."""
        for prio in [0, -100, 100, -2147483648, 2147483647]:
            result = self.validator.validate_priority(prio)
            assert result.valid is True

    def test_validate_priority_invalid(self):
        """Test validating invalid priority."""
        result = self.validator.validate_priority("not a number")
        assert result.valid is False

    def test_validate_policy_valid(self):
        """Test validating valid policies."""
        for policy in ["accept", "drop"]:
            result = self.validator.validate_policy(policy)
            assert result.valid is True

    def test_validate_policy_invalid(self):
        """Test validating invalid policy."""
        result = self.validator.validate_policy("reject")
        assert result.valid is False

    def test_validate_ip_address_v4(self):
        """Test validating IPv4 address."""
        result = self.validator.validate_ip_address("192.168.1.1")
        assert result.valid is True

    def test_validate_ip_address_v6(self):
        """Test validating IPv6 address."""
        result = self.validator.validate_ip_address("2001:db8::1")
        assert result.valid is True

    def test_validate_ip_address_invalid(self):
        """Test validating invalid IP address."""
        result = self.validator.validate_ip_address("not.an.ip")
        assert result.valid is False

    def test_validate_ip_network_valid(self):
        """Test validating valid IP network."""
        result = self.validator.validate_ip_network("192.168.1.0/24")
        assert result.valid is True

    def test_validate_ip_network_invalid(self):
        """Test validating invalid IP network."""
        result = self.validator.validate_ip_network("192.168.1.0/33")
        assert result.valid is False

    def test_validate_port_valid(self):
        """Test validating valid ports."""
        for port in [22, 80, 443, 0, 65535]:
            result = self.validator.validate_port(port)
            assert result.valid is True

    def test_validate_port_well_known(self):
        """Test validating well-known port names."""
        result = self.validator.validate_port("ssh")
        assert result.valid is True

    def test_validate_port_invalid(self):
        """Test validating invalid port."""
        result = self.validator.validate_port(65536)
        assert result.valid is False

    def test_validate_port_range_valid(self):
        """Test validating valid port range."""
        result = self.validator.validate_port_range("80-443")
        assert result.valid is True

    def test_validate_port_range_invalid_order(self):
        """Test validating port range with wrong order."""
        result = self.validator.validate_port_range("443-80")
        assert result.valid is False

    def test_validate_interface_valid(self):
        """Test validating valid interface names."""
        for iface in ["eth0", "wlan0", "br-lan", "veth*"]:
            result = self.validator.validate_interface(iface)
            assert result.valid is True

    def test_validate_interface_too_long(self):
        """Test validating too long interface name."""
        result = self.validator.validate_interface("a" * 16)
        assert result.valid is False

    def test_validate_mac_address_valid(self):
        """Test validating valid MAC address."""
        result = self.validator.validate_mac_address("00:11:22:33:44:55")
        assert result.valid is True

    def test_validate_mac_address_invalid(self):
        """Test validating invalid MAC address."""
        result = self.validator.validate_mac_address("00:11:22:33:44")
        assert result.valid is False

    def test_validate_set_type_valid(self):
        """Test validating valid set types."""
        for set_type in ["ipv4_addr", "inet_service", "ipv4_addr . inet_service"]:
            result = self.validator.validate_set_type(set_type)
            assert result.valid is True

    def test_validate_set_type_invalid(self):
        """Test validating invalid set type."""
        result = self.validator.validate_set_type("invalid_type")
        assert result.valid is False
