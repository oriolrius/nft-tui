"""Table view widget for displaying rules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual.message import Message
from textual.widgets import DataTable

if TYPE_CHECKING:
    from ..nft.models import Chain, Rule, Set, Table


class RuleTable(DataTable):
    """DataTable widget for displaying rules in a chain."""

    BINDINGS = [
        ("j", "cursor_down", "Down"),
        ("k", "cursor_up", "Up"),
        ("g", "scroll_top", "Top"),
        ("G", "scroll_bottom", "Bottom"),
        ("enter", "select_cursor", "Select"),
    ]

    class RuleSelected(Message):
        """Message sent when a rule is selected."""

        def __init__(self, rule: Rule, chain: Chain, table: Table) -> None:
            super().__init__()
            self.rule = rule
            self.chain = chain
            self.table = table

    def __init__(
        self,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the rule table."""
        super().__init__(id=id, classes=classes, cursor_type="row")
        self._rules: list[Rule] = []
        self._chain: Chain | None = None
        self._table: Table | None = None

    def on_mount(self) -> None:
        """Set up the table columns when mounted."""
        self.add_column("#", width=4, key="index")
        self.add_column("Handle", width=8, key="handle")
        self.add_column("Rule", key="rule")
        self.add_column("Packets", width=10, key="packets")
        self.add_column("Bytes", width=10, key="bytes")
        self.add_column("Comment", width=20, key="comment")

    def load_chain(self, chain: Chain, table: Table) -> None:
        """Load rules from a chain into the table."""
        self._chain = chain
        self._table = table
        self._rules = chain.rules

        self.clear()

        for i, rule in enumerate(chain.rules, 1):
            self._add_rule_row(i, rule)

    def _add_rule_row(self, index: int, rule: Rule) -> None:
        """Add a rule row to the table."""
        # Format the rule expression
        rule_text = self._format_rule_expr(rule)

        # Format counter values
        if rule.counter:
            packets = rule.counter.format_packets()
            bytes_str = rule.counter.format_bytes()
        else:
            packets = "-"
            bytes_str = "-"

        # Format comment
        comment = rule.comment or ""
        if len(comment) > 18:
            comment = comment[:17] + "..."

        self.add_row(
            str(index),
            str(rule.handle),
            rule_text,
            packets,
            bytes_str,
            comment,
            key=str(rule.handle),
        )

    def _format_rule_expr(self, rule: Rule) -> Text:
        """Format rule expression with syntax highlighting."""
        text = Text()
        expr_str = rule.format_expr()

        # Simple syntax highlighting
        keywords = {
            "accept": "green bold",
            "drop": "red bold",
            "reject": "red bold",
            "return": "yellow",
            "jump": "cyan",
            "goto": "cyan",
            "masquerade": "magenta",
            "snat": "magenta",
            "dnat": "magenta",
            "log": "blue",
            "counter": "dim",
            "limit": "yellow",
        }

        protocols = {
            "tcp": "cyan",
            "udp": "cyan",
            "icmp": "cyan",
            "icmpv6": "cyan",
        }

        meta_keys = {
            "iifname": "green",
            "oifname": "blue",
            "iif": "green",
            "oif": "blue",
            "mark": "yellow",
            "priority": "yellow",
        }

        parts = expr_str.split()
        for i, part in enumerate(parts):
            if i > 0:
                text.append(" ")

            lower_part = part.lower()

            if lower_part in keywords:
                text.append(part, style=keywords[lower_part])
            elif lower_part in protocols:
                text.append(part, style=protocols[lower_part])
            elif lower_part in meta_keys:
                text.append(part, style=meta_keys[lower_part])
            elif lower_part in ("dport", "sport"):
                text.append(part, style="cyan dim")
            elif lower_part in ("saddr", "daddr"):
                text.append(part, style="yellow dim")
            elif lower_part == "ct":
                text.append(part, style="magenta dim")
            elif lower_part == "state":
                text.append(part, style="magenta dim")
            elif lower_part in ("established", "related", "new", "invalid"):
                text.append(part, style="magenta")
            elif part.startswith("@"):
                text.append(part, style="yellow")
            elif part.startswith("{") or part.endswith("}"):
                text.append(part, style="dim")
            else:
                text.append(part)

        return text

    def refresh_counters(self, rules: list[Rule]) -> None:
        """Refresh counter values for all rules."""
        self._rules = rules

        for rule in rules:
            try:
                row_key = str(rule.handle)
                if rule.counter:
                    self.update_cell(
                        row_key, "packets", rule.counter.format_packets()
                    )
                    self.update_cell(
                        row_key, "bytes", rule.counter.format_bytes()
                    )
            except Exception:
                pass

    def get_selected_rule(self) -> Rule | None:
        """Get the currently selected rule."""
        if self.cursor_row is None or self.cursor_row >= len(self._rules):
            return None
        return self._rules[self.cursor_row]

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection."""
        if (
            self._chain
            and self._table
            and event.cursor_row < len(self._rules)
        ):
            rule = self._rules[event.cursor_row]
            self.post_message(
                self.RuleSelected(rule, self._chain, self._table)
            )

    def action_scroll_top(self) -> None:
        """Scroll to the top of the table."""
        self.cursor_coordinate = (0, self.cursor_column)

    def action_scroll_bottom(self) -> None:
        """Scroll to the bottom of the table."""
        if self.row_count > 0:
            self.cursor_coordinate = (self.row_count - 1, self.cursor_column)


class SetElementTable(DataTable):
    """DataTable widget for displaying set elements."""

    def __init__(
        self,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the set element table."""
        super().__init__(id=id, classes=classes, cursor_type="row")
        self._set: Set | None = None

    def on_mount(self) -> None:
        """Set up the table columns when mounted."""
        self.add_column("Element", key="element")
        self.add_column("Timeout", width=10, key="timeout")
        self.add_column("Expires", width=10, key="expires")
        self.add_column("Packets", width=10, key="packets")
        self.add_column("Bytes", width=10, key="bytes")
        self.add_column("Comment", width=20, key="comment")

    def load_set(self, nft_set: Set) -> None:
        """Load elements from a set into the table."""
        self._set = nft_set

        self.clear()

        for elem in nft_set.elements:
            timeout = f"{elem.timeout}s" if elem.timeout else "-"
            expires = f"{elem.expires}s" if elem.expires else "-"

            if elem.counter:
                packets = elem.counter.format_packets()
                bytes_str = elem.counter.format_bytes()
            else:
                packets = "-"
                bytes_str = "-"

            comment = elem.comment or ""
            if len(comment) > 18:
                comment = comment[:17] + "..."

            self.add_row(
                str(elem.value),
                timeout,
                expires,
                packets,
                bytes_str,
                comment,
            )
