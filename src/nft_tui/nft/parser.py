"""JSON parser for nftables output."""

from __future__ import annotations

import json
from typing import Any

from .models import Chain, Counter, Rule, RuleSet, Set, SetElement, Table


class NFTParser:
    """Parser for nftables JSON output."""

    def parse_ruleset(self, json_output: str) -> RuleSet:
        """Parse complete ruleset from nft -j list ruleset output."""
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON output from nft: {e}") from e

        if "nftables" not in data:
            raise ValueError("Invalid nftables JSON: missing 'nftables' key")

        ruleset = RuleSet()
        items = data["nftables"]

        tables: dict[tuple[str, str], Table] = {}
        chains: dict[tuple[str, str, str], Chain] = {}
        sets: dict[tuple[str, str, str], Set] = {}

        for item in items:
            if "metainfo" in item:
                ruleset.metainfo = item["metainfo"]
            elif "table" in item:
                table = self._parse_table(item["table"])
                key = (table.family, table.name)
                tables[key] = table
            elif "chain" in item:
                chain = self._parse_chain(item["chain"])
                key = (chain.family, chain.table, chain.name)
                chains[key] = chain
            elif "rule" in item:
                rule = self._parse_rule(item["rule"])
                chain_key = (rule.family, rule.table, rule.chain)
                if chain_key in chains:
                    chains[chain_key].rules.append(rule)
            elif "set" in item:
                nft_set = self._parse_set(item["set"])
                key = (nft_set.family, nft_set.table, nft_set.name)
                sets[key] = nft_set

        for (family, table_name), table in tables.items():
            for (cf, ct, cn), chain in chains.items():
                if cf == family and ct == table_name:
                    for i, rule in enumerate(chain.rules):
                        rule.index = i + 1
                    table.chains.append(chain)
            for (sf, st, sn), nft_set in sets.items():
                if sf == family and st == table_name:
                    table.sets.append(nft_set)

            table.chains.sort(key=lambda c: c.name)
            table.sets.sort(key=lambda s: s.name)
            ruleset.tables.append(table)

        ruleset.tables.sort(key=lambda t: (t.family, t.name))
        return ruleset

    def _parse_table(self, data: dict[str, Any]) -> Table:
        """Parse a table object."""
        return Table(
            family=data.get("family", "ip"),
            name=data.get("name", ""),
            handle=data.get("handle", 0),
            flags=data.get("flags", []),
        )

    def _parse_chain(self, data: dict[str, Any]) -> Chain:
        """Parse a chain object."""
        return Chain(
            family=data.get("family", "ip"),
            table=data.get("table", ""),
            name=data.get("name", ""),
            handle=data.get("handle", 0),
            type=data.get("type"),
            hook=data.get("hook"),
            priority=data.get("prio"),
            policy=data.get("policy"),
            device=data.get("dev"),
        )

    def _parse_rule(self, data: dict[str, Any]) -> Rule:
        """Parse a rule object."""
        expr = data.get("expr", [])
        counter = None
        comment = None

        for item in expr:
            if "counter" in item:
                c = item["counter"]
                counter = Counter(
                    packets=c.get("packets", 0),
                    bytes=c.get("bytes", 0),
                )
            if "comment" in item:
                comment = item["comment"]

        if data.get("comment"):
            comment = data["comment"]

        return Rule(
            family=data.get("family", "ip"),
            table=data.get("table", ""),
            chain=data.get("chain", ""),
            handle=data.get("handle", 0),
            expr=expr,
            comment=comment,
            counter=counter,
        )

    def _parse_set(self, data: dict[str, Any]) -> Set:
        """Parse a set object."""
        elements = []
        raw_elements = data.get("elem", [])

        for elem in raw_elements:
            if isinstance(elem, dict):
                if "elem" in elem:
                    elem_data = elem["elem"]
                    elements.append(
                        SetElement(
                            value=elem_data.get("val"),
                            timeout=elem_data.get("timeout"),
                            expires=elem_data.get("expires"),
                            comment=elem_data.get("comment"),
                            counter=self._parse_counter(elem_data.get("counter")),
                        )
                    )
                else:
                    elements.append(SetElement(value=elem))
            else:
                elements.append(SetElement(value=elem))

        return Set(
            family=data.get("family", "ip"),
            table=data.get("table", ""),
            name=data.get("name", ""),
            handle=data.get("handle", 0),
            type=data.get("type", ""),
            flags=data.get("flags", []),
            elements=elements,
            timeout=data.get("timeout"),
            gc_interval=data.get("gc-interval"),
            size=data.get("size"),
            policy=data.get("policy"),
            comment=data.get("comment"),
        )

    def _parse_counter(self, data: dict[str, Any] | None) -> Counter | None:
        """Parse a counter object."""
        if not data:
            return None
        return Counter(
            packets=data.get("packets", 0),
            bytes=data.get("bytes", 0),
        )

    def parse_tables(self, json_output: str) -> list[Table]:
        """Parse tables from nft -j list tables output."""
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON output from nft: {e}") from e

        tables = []
        for item in data.get("nftables", []):
            if "table" in item:
                tables.append(self._parse_table(item["table"]))

        return tables

    def parse_chains(self, json_output: str) -> list[Chain]:
        """Parse chains from nft -j list chains output."""
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON output from nft: {e}") from e

        chains = []
        for item in data.get("nftables", []):
            if "chain" in item:
                chains.append(self._parse_chain(item["chain"]))

        return chains
