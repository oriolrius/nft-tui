"""Tests for JSON parser."""

import pytest

from nft_tui.nft.parser import NFTParser


class TestNFTParser:
    """Tests for NFTParser class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.parser = NFTParser()

    def test_parse_empty_ruleset(self):
        """Test parsing empty ruleset."""
        json_output = '{"nftables": [{"metainfo": {"version": "1.0.2"}}]}'
        ruleset = self.parser.parse_ruleset(json_output)
        assert len(ruleset.tables) == 0
        assert ruleset.version == "1.0.2"

    def test_parse_table(self):
        """Test parsing a table."""
        json_output = """{
            "nftables": [
                {"metainfo": {"version": "1.0.2"}},
                {"table": {"family": "inet", "name": "filter", "handle": 1}}
            ]
        }"""
        ruleset = self.parser.parse_ruleset(json_output)
        assert len(ruleset.tables) == 1
        assert ruleset.tables[0].family == "inet"
        assert ruleset.tables[0].name == "filter"

    def test_parse_chain(self):
        """Test parsing a chain."""
        json_output = """{
            "nftables": [
                {"metainfo": {"version": "1.0.2"}},
                {"table": {"family": "inet", "name": "filter", "handle": 1}},
                {
                    "chain": {
                        "family": "inet",
                        "table": "filter",
                        "name": "input",
                        "handle": 1,
                        "type": "filter",
                        "hook": "input",
                        "prio": 0,
                        "policy": "accept"
                    }
                }
            ]
        }"""
        ruleset = self.parser.parse_ruleset(json_output)
        assert len(ruleset.tables) == 1
        assert len(ruleset.tables[0].chains) == 1

        chain = ruleset.tables[0].chains[0]
        assert chain.name == "input"
        assert chain.type == "filter"
        assert chain.hook == "input"
        assert chain.priority == 0
        assert chain.policy == "accept"

    def test_parse_rule(self):
        """Test parsing a rule."""
        json_output = """{
            "nftables": [
                {"metainfo": {"version": "1.0.2"}},
                {"table": {"family": "inet", "name": "filter", "handle": 1}},
                {
                    "chain": {
                        "family": "inet",
                        "table": "filter",
                        "name": "input",
                        "handle": 1
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "filter",
                        "chain": "input",
                        "handle": 2,
                        "expr": [
                            {"accept": null}
                        ]
                    }
                }
            ]
        }"""
        ruleset = self.parser.parse_ruleset(json_output)
        assert len(ruleset.tables[0].chains[0].rules) == 1

        rule = ruleset.tables[0].chains[0].rules[0]
        assert rule.handle == 2
        assert rule.format_expr() == "accept"

    def test_parse_rule_with_counter(self):
        """Test parsing a rule with counter."""
        json_output = """{
            "nftables": [
                {"metainfo": {"version": "1.0.2"}},
                {"table": {"family": "inet", "name": "filter", "handle": 1}},
                {
                    "chain": {
                        "family": "inet",
                        "table": "filter",
                        "name": "input",
                        "handle": 1
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "filter",
                        "chain": "input",
                        "handle": 2,
                        "expr": [
                            {"counter": {"packets": 100, "bytes": 5000}},
                            {"accept": null}
                        ]
                    }
                }
            ]
        }"""
        ruleset = self.parser.parse_ruleset(json_output)
        rule = ruleset.tables[0].chains[0].rules[0]
        assert rule.counter is not None
        assert rule.counter.packets == 100
        assert rule.counter.bytes == 5000

    def test_parse_set(self):
        """Test parsing a set."""
        json_output = """{
            "nftables": [
                {"metainfo": {"version": "1.0.2"}},
                {"table": {"family": "inet", "name": "filter", "handle": 1}},
                {
                    "set": {
                        "family": "inet",
                        "table": "filter",
                        "name": "allowed_ips",
                        "handle": 1,
                        "type": "ipv4_addr",
                        "flags": ["interval"]
                    }
                }
            ]
        }"""
        ruleset = self.parser.parse_ruleset(json_output)
        assert len(ruleset.tables[0].sets) == 1

        nft_set = ruleset.tables[0].sets[0]
        assert nft_set.name == "allowed_ips"
        assert nft_set.type == "ipv4_addr"
        assert "interval" in nft_set.flags

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON."""
        with pytest.raises(ValueError, match="Invalid JSON"):
            self.parser.parse_ruleset("not json")

    def test_parse_missing_nftables_key(self):
        """Test parsing JSON without nftables key."""
        with pytest.raises(ValueError, match="missing 'nftables'"):
            self.parser.parse_ruleset('{"other": "data"}')
