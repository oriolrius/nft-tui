"""Tests for data models."""

import pytest

from nft_tui.nft.models import Chain, Counter, Rule, RuleSet, Set, Table


class TestCounter:
    """Tests for Counter class."""

    def test_format_packets_small(self):
        """Test packet formatting for small numbers."""
        counter = Counter(packets=500, bytes=0)
        assert counter.format_packets() == "500"

    def test_format_packets_thousands(self):
        """Test packet formatting for thousands."""
        counter = Counter(packets=1500, bytes=0)
        assert counter.format_packets() == "1.5K"

    def test_format_packets_millions(self):
        """Test packet formatting for millions."""
        counter = Counter(packets=1_500_000, bytes=0)
        assert counter.format_packets() == "1.5M"

    def test_format_packets_billions(self):
        """Test packet formatting for billions."""
        counter = Counter(packets=1_500_000_000, bytes=0)
        assert counter.format_packets() == "1.5G"

    def test_format_bytes_small(self):
        """Test byte formatting for small numbers."""
        counter = Counter(packets=0, bytes=500)
        assert counter.format_bytes() == "500B"

    def test_format_bytes_kilobytes(self):
        """Test byte formatting for kilobytes."""
        counter = Counter(packets=0, bytes=1536)
        assert counter.format_bytes() == "1.5KB"

    def test_format_bytes_megabytes(self):
        """Test byte formatting for megabytes."""
        counter = Counter(packets=0, bytes=1_572_864)
        assert counter.format_bytes() == "1.5MB"

    def test_format_bytes_gigabytes(self):
        """Test byte formatting for gigabytes."""
        counter = Counter(packets=0, bytes=1_610_612_736)
        assert counter.format_bytes() == "1.5GB"


class TestRule:
    """Tests for Rule class."""

    def test_format_expr_accept(self):
        """Test formatting accept action."""
        rule = Rule(
            family="inet",
            table="filter",
            chain="input",
            handle=1,
            expr=[{"accept": None}],
        )
        assert rule.format_expr() == "accept"

    def test_format_expr_drop(self):
        """Test formatting drop action."""
        rule = Rule(
            family="inet",
            table="filter",
            chain="input",
            handle=1,
            expr=[{"drop": None}],
        )
        assert rule.format_expr() == "drop"

    def test_format_expr_match(self):
        """Test formatting match expression."""
        rule = Rule(
            family="inet",
            table="filter",
            chain="input",
            handle=1,
            expr=[
                {
                    "match": {
                        "op": "==",
                        "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                        "right": 22,
                    }
                },
                {"accept": None},
            ],
        )
        result = rule.format_expr()
        assert "tcp" in result
        assert "dport" in result
        assert "22" in result
        assert "accept" in result

    def test_format_expr_empty(self):
        """Test formatting empty expression."""
        rule = Rule(
            family="inet",
            table="filter",
            chain="input",
            handle=1,
            expr=[],
        )
        assert rule.format_expr() == "(empty rule)"


class TestChain:
    """Tests for Chain class."""

    def test_is_base_chain_true(self):
        """Test base chain detection."""
        chain = Chain(
            family="inet",
            table="filter",
            name="input",
            handle=1,
            type="filter",
            hook="input",
            priority=0,
            policy="accept",
        )
        assert chain.is_base_chain is True

    def test_is_base_chain_false(self):
        """Test regular chain detection."""
        chain = Chain(
            family="inet",
            table="filter",
            name="custom",
            handle=1,
        )
        assert chain.is_base_chain is False

    def test_display_info_base_chain(self):
        """Test display info for base chain."""
        chain = Chain(
            family="inet",
            table="filter",
            name="input",
            handle=1,
            type="filter",
            hook="input",
            priority=0,
        )
        info = chain.display_info
        assert "type: filter" in info
        assert "hook: input" in info
        assert "priority: 0" in info


class TestTable:
    """Tests for Table class."""

    def test_full_name(self):
        """Test full name property."""
        table = Table(family="inet", name="filter", handle=1)
        assert table.full_name == "inet::filter"


class TestRuleSet:
    """Tests for RuleSet class."""

    def test_get_table_found(self):
        """Test finding an existing table."""
        table = Table(family="inet", name="filter", handle=1)
        ruleset = RuleSet(tables=[table])
        result = ruleset.get_table("inet", "filter")
        assert result is table

    def test_get_table_not_found(self):
        """Test finding a non-existent table."""
        ruleset = RuleSet(tables=[])
        result = ruleset.get_table("inet", "filter")
        assert result is None

    def test_total_rules(self):
        """Test total rules count."""
        rule1 = Rule(family="inet", table="filter", chain="input", handle=1)
        rule2 = Rule(family="inet", table="filter", chain="input", handle=2)
        chain = Chain(
            family="inet",
            table="filter",
            name="input",
            handle=1,
            rules=[rule1, rule2],
        )
        table = Table(family="inet", name="filter", handle=1, chains=[chain])
        ruleset = RuleSet(tables=[table])
        assert ruleset.total_rules() == 2

    def test_total_chains(self):
        """Test total chains count."""
        chain1 = Chain(family="inet", table="filter", name="input", handle=1)
        chain2 = Chain(family="inet", table="filter", name="output", handle=2)
        table = Table(
            family="inet",
            name="filter",
            handle=1,
            chains=[chain1, chain2],
        )
        ruleset = RuleSet(tables=[table])
        assert ruleset.total_chains() == 2
