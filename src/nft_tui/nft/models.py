"""Data models for nftables objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Family(str, Enum):
    """Address family types."""

    IP = "ip"
    IP6 = "ip6"
    INET = "inet"
    ARP = "arp"
    BRIDGE = "bridge"
    NETDEV = "netdev"


class ChainType(str, Enum):
    """Chain types."""

    FILTER = "filter"
    NAT = "nat"
    ROUTE = "route"


class ChainHook(str, Enum):
    """Chain hook points."""

    PREROUTING = "prerouting"
    INPUT = "input"
    FORWARD = "forward"
    OUTPUT = "output"
    POSTROUTING = "postrouting"
    INGRESS = "ingress"
    EGRESS = "egress"


class ChainPolicy(str, Enum):
    """Chain default policies."""

    ACCEPT = "accept"
    DROP = "drop"


@dataclass
class Counter:
    """Packet and byte counter."""

    packets: int = 0
    bytes: int = 0

    def format_packets(self) -> str:
        """Format packet count with human-readable suffix."""
        return self._format_number(self.packets)

    def format_bytes(self) -> str:
        """Format byte count with human-readable suffix."""
        return self._format_size(self.bytes)

    @staticmethod
    def _format_number(n: int) -> str:
        """Format number with K/M/G suffix."""
        if n >= 1_000_000_000:
            return f"{n / 1_000_000_000:.1f}G"
        if n >= 1_000_000:
            return f"{n / 1_000_000:.1f}M"
        if n >= 1_000:
            return f"{n / 1_000:.1f}K"
        return str(n)

    @staticmethod
    def _format_size(n: int) -> str:
        """Format bytes with human-readable suffix."""
        if n >= 1_099_511_627_776:
            return f"{n / 1_099_511_627_776:.1f}TB"
        if n >= 1_073_741_824:
            return f"{n / 1_073_741_824:.1f}GB"
        if n >= 1_048_576:
            return f"{n / 1_048_576:.1f}MB"
        if n >= 1_024:
            return f"{n / 1_024:.1f}KB"
        return f"{n}B"


@dataclass
class Rule:
    """An nftables rule."""

    family: str
    table: str
    chain: str
    handle: int
    expr: list[dict[str, Any]] = field(default_factory=list)
    comment: str | None = None
    counter: Counter | None = None
    index: int | None = None

    def format_expr(self) -> str:
        """Format rule expression as human-readable string."""
        parts: list[str] = []

        for item in self.expr:
            part = self._format_expr_item(item)
            if part:
                parts.append(part)

        return " ".join(parts) if parts else "(empty rule)"

    def _format_expr_item(self, item: dict[str, Any]) -> str:
        """Format a single expression item."""
        if "match" in item:
            return self._format_match(item["match"])
        if "counter" in item:
            return ""  # Counter shown separately
        if "accept" in item:
            return "accept"
        if "drop" in item:
            return "drop"
        if "reject" in item:
            return "reject"
        if "return" in item:
            return "return"
        if "jump" in item:
            return f"jump {item['jump']['target']}"
        if "goto" in item:
            return f"goto {item['goto']['target']}"
        if "masquerade" in item:
            return "masquerade"
        if "snat" in item:
            return self._format_nat(item["snat"], "snat")
        if "dnat" in item:
            return self._format_nat(item["dnat"], "dnat")
        if "redirect" in item:
            return self._format_redirect(item["redirect"])
        if "log" in item:
            return self._format_log(item["log"])
        if "limit" in item:
            return self._format_limit(item["limit"])
        if "ct" in item:
            return ""  # CT helper, skip
        if "xt" in item:
            return "(xt match)"  # xtables compat

        return ""

    def _format_match(self, match: dict[str, Any]) -> str:
        """Format a match expression."""
        op = match.get("op", "==")
        left = self._format_expr_value(match.get("left", {}))
        right = self._format_expr_value(match.get("right", {}))

        op_str = {
            "==": "",
            "!=": "!=",
            "<": "<",
            ">": ">",
            "<=": "<=",
            ">=": ">=",
            "in": "",
        }.get(op, op)

        if op == "==" or op == "in":
            return f"{left} {right}"
        return f"{left} {op_str} {right}"

    def _format_expr_value(self, value: Any) -> str:
        """Format an expression value."""
        if isinstance(value, dict):
            if "meta" in value:
                return value["meta"]["key"]
            if "payload" in value:
                p = value["payload"]
                proto = p.get("protocol", "")
                fld = p.get("field", "")
                return f"{proto} {fld}" if proto else fld
            if "ct" in value:
                return f"ct {value['ct']['key']}"
            if "prefix" in value:
                addr = value["prefix"]["addr"]
                length = value["prefix"]["len"]
                return f"{addr}/{length}"
            if "range" in value:
                return f"{value['range'][0]}-{value['range'][1]}"
            if "set" in value:
                items = value["set"]
                if isinstance(items, list) and len(items) <= 3:
                    return "{ " + ", ".join(str(i) for i in items) + " }"
                return f"@{items}" if isinstance(items, str) else "{ ... }"
            return str(value)
        if isinstance(value, list):
            return "{ " + ", ".join(str(v) for v in value) + " }"
        return str(value)

    def _format_nat(self, nat: dict[str, Any], nat_type: str) -> str:
        """Format NAT expression."""
        addr = nat.get("addr", "")
        port = nat.get("port", "")
        if addr and port:
            return f"{nat_type} to {addr}:{port}"
        if addr:
            return f"{nat_type} to {addr}"
        return nat_type

    def _format_redirect(self, redirect: dict[str, Any]) -> str:
        """Format redirect expression."""
        port = redirect.get("port", "")
        if port:
            return f"redirect to :{port}"
        return "redirect"

    def _format_log(self, log: dict[str, Any]) -> str:
        """Format log expression."""
        prefix = log.get("prefix", "")
        if prefix:
            return f'log prefix "{prefix}"'
        return "log"

    def _format_limit(self, limit: dict[str, Any]) -> str:
        """Format limit expression."""
        rate = limit.get("rate", 0)
        unit = limit.get("per", "second")
        burst = limit.get("burst", 0)
        result = f"limit rate {rate}/{unit}"
        if burst:
            result += f" burst {burst}"
        return result


@dataclass
class SetElement:
    """An element in an nftables set."""

    value: Any
    timeout: int | None = None
    expires: int | None = None
    comment: str | None = None
    counter: Counter | None = None


@dataclass
class Set:
    """An nftables set."""

    family: str
    table: str
    name: str
    handle: int
    type: str | list[str]
    flags: list[str] = field(default_factory=list)
    elements: list[SetElement] = field(default_factory=list)
    timeout: int | None = None
    gc_interval: int | None = None
    size: int | None = None
    policy: str | None = None
    comment: str | None = None

    @property
    def type_str(self) -> str:
        """Get type as string."""
        if isinstance(self.type, list):
            return " . ".join(self.type)
        return self.type


@dataclass
class Chain:
    """An nftables chain."""

    family: str
    table: str
    name: str
    handle: int
    type: str | None = None
    hook: str | None = None
    priority: int | None = None
    policy: str | None = None
    device: str | None = None
    rules: list[Rule] = field(default_factory=list)

    @property
    def is_base_chain(self) -> bool:
        """Check if this is a base chain (has hook)."""
        return self.hook is not None

    @property
    def display_info(self) -> str:
        """Get display info string."""
        if self.is_base_chain:
            parts = []
            if self.type:
                parts.append(f"type: {self.type}")
            if self.hook:
                parts.append(f"hook: {self.hook}")
            if self.priority is not None:
                parts.append(f"priority: {self.priority}")
            if self.device:
                parts.append(f"device: {self.device}")
            return ", ".join(parts)
        return "regular chain"


@dataclass
class Table:
    """An nftables table."""

    family: str
    name: str
    handle: int
    flags: list[str] = field(default_factory=list)
    chains: list[Chain] = field(default_factory=list)
    sets: list[Set] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        """Get full name with family."""
        return f"{self.family}::{self.name}"


@dataclass
class RuleSet:
    """Complete nftables ruleset."""

    tables: list[Table] = field(default_factory=list)
    metainfo: dict[str, Any] = field(default_factory=dict)

    @property
    def version(self) -> str:
        """Get nftables version."""
        return self.metainfo.get("version", "unknown")

    @property
    def json_schema_version(self) -> int:
        """Get JSON schema version."""
        return self.metainfo.get("json_schema_version", 0)

    def get_table(self, family: str, name: str) -> Table | None:
        """Find a table by family and name."""
        for table in self.tables:
            if table.family == family and table.name == name:
                return table
        return None

    def get_chain(self, family: str, table: str, chain: str) -> Chain | None:
        """Find a chain by family, table, and chain name."""
        t = self.get_table(family, table)
        if t:
            for c in t.chains:
                if c.name == chain:
                    return c
        return None

    def get_rule(self, family: str, table: str, chain: str, handle: int) -> Rule | None:
        """Find a rule by its handle."""
        c = self.get_chain(family, table, chain)
        if c:
            for r in c.rules:
                if r.handle == handle:
                    return r
        return None

    def total_rules(self) -> int:
        """Get total number of rules."""
        count = 0
        for table in self.tables:
            for chain in table.chains:
                count += len(chain.rules)
        return count

    def total_chains(self) -> int:
        """Get total number of chains."""
        count = 0
        for table in self.tables:
            count += len(table.chains)
        return count


@dataclass
class Connection:
    """A connection tracking entry."""

    protocol: str
    state: str
    src: str
    dst: str
    sport: int | None
    dport: int | None
    packets_orig: int
    bytes_orig: int
    packets_reply: int
    bytes_reply: int
    timeout: int | None = None
    mark: int | None = None
    zone: int | None = None
    assured: bool = False
    unreplied: bool = False

    @property
    def display_src(self) -> str:
        """Format source address:port."""
        if self.sport:
            return f"{self.src}:{self.sport}"
        return self.src

    @property
    def display_dst(self) -> str:
        """Format destination address:port."""
        if self.dport:
            return f"{self.dst}:{self.dport}"
        return self.dst
