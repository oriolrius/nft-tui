"""Counter display widgets."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

if TYPE_CHECKING:
    from ..nft.models import Chain, Counter, RuleSet


class CounterCard(Static):
    """A card displaying counter statistics."""

    def __init__(
        self,
        label: str,
        value: str = "0",
        subtitle: str = "",
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the counter card."""
        super().__init__(id=id, classes=classes)
        self._label = label
        self._value = value
        self._subtitle = subtitle

    def render(self) -> Text:
        """Render the counter card."""
        text = Text()
        text.append(self._label + "\n", style="dim")
        text.append(self._value, style="bold cyan")
        if self._subtitle:
            text.append("\n" + self._subtitle, style="dim italic")
        return text

    def update_value(self, value: str, subtitle: str = "") -> None:
        """Update the displayed value."""
        self._value = value
        self._subtitle = subtitle
        self.refresh()


class CounterDisplay(Widget):
    """Widget for displaying counter statistics."""

    auto_refresh: reactive[bool] = reactive(False)
    refresh_interval: reactive[float] = reactive(2.0)

    def __init__(
        self,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the counter display."""
        super().__init__(id=id, classes=classes)
        self._total_packets = CounterCard("Total Packets", "0", id="total-packets")
        self._total_bytes = CounterCard("Total Bytes", "0 B", id="total-bytes")
        self._tables_count = CounterCard("Tables", "0", id="tables-count")
        self._chains_count = CounterCard("Chains", "0", id="chains-count")
        self._rules_count = CounterCard("Rules", "0", id="rules-count")
        self._timer_handle = None

    def compose(self):
        """Compose the counter display layout."""
        with Horizontal(classes="counter-row"):
            yield self._total_packets
            yield self._total_bytes
        with Horizontal(classes="counter-row"):
            yield self._tables_count
            yield self._chains_count
            yield self._rules_count

    def update_from_ruleset(self, ruleset: RuleSet) -> None:
        """Update counters from a ruleset."""
        total_packets = 0
        total_bytes = 0
        total_rules = 0
        total_chains = 0

        for table in ruleset.tables:
            total_chains += len(table.chains)
            for chain in table.chains:
                total_rules += len(chain.rules)
                for rule in chain.rules:
                    if rule.counter:
                        total_packets += rule.counter.packets
                        total_bytes += rule.counter.bytes

        self._total_packets.update_value(self._format_number(total_packets))
        self._total_bytes.update_value(self._format_bytes(total_bytes))
        self._tables_count.update_value(str(len(ruleset.tables)))
        self._chains_count.update_value(str(total_chains))
        self._rules_count.update_value(str(total_rules))

    def update_from_chain(self, chain: Chain) -> None:
        """Update counters from a single chain."""
        total_packets = 0
        total_bytes = 0

        for rule in chain.rules:
            if rule.counter:
                total_packets += rule.counter.packets
                total_bytes += rule.counter.bytes

        self._total_packets.update_value(
            self._format_number(total_packets),
            f"in {len(chain.rules)} rules",
        )
        self._total_bytes.update_value(self._format_bytes(total_bytes))

    @staticmethod
    def _format_number(n: int) -> str:
        """Format a large number with suffixes."""
        if n >= 1_000_000_000:
            return f"{n / 1_000_000_000:.2f}G"
        if n >= 1_000_000:
            return f"{n / 1_000_000:.2f}M"
        if n >= 1_000:
            return f"{n / 1_000:.2f}K"
        return str(n)

    @staticmethod
    def _format_bytes(n: int) -> str:
        """Format bytes with appropriate unit."""
        if n >= 1_099_511_627_776:
            return f"{n / 1_099_511_627_776:.2f} TB"
        if n >= 1_073_741_824:
            return f"{n / 1_073_741_824:.2f} GB"
        if n >= 1_048_576:
            return f"{n / 1_048_576:.2f} MB"
        if n >= 1_024:
            return f"{n / 1_024:.2f} KB"
        return f"{n} B"


class ChainInfoPanel(Static):
    """Panel displaying chain information."""

    def __init__(
        self,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the chain info panel."""
        super().__init__(id=id, classes=classes)
        self._chain: Chain | None = None

    def set_chain(self, chain: Chain | None) -> None:
        """Set the chain to display."""
        self._chain = chain
        self.refresh()

    def render(self) -> Text:
        """Render the chain info panel."""
        if not self._chain:
            return Text("Select a chain to view details", style="dim italic")

        chain = self._chain
        text = Text()

        # Chain name and type
        text.append("Chain: ", style="dim")
        text.append(chain.name, style="bold white")
        text.append("\n")

        # Table info
        text.append("Table: ", style="dim")
        text.append(f"{chain.family}::{chain.table}", style="cyan")
        text.append("\n")

        if chain.is_base_chain:
            # Type
            if chain.type:
                text.append("Type: ", style="dim")
                text.append(chain.type, style="yellow")
                text.append("\n")

            # Hook
            if chain.hook:
                text.append("Hook: ", style="dim")
                text.append(chain.hook, style="green")
                text.append("\n")

            # Priority
            if chain.priority is not None:
                text.append("Priority: ", style="dim")
                text.append(str(chain.priority), style="white")
                text.append("\n")

            # Policy
            if chain.policy:
                text.append("Policy: ", style="dim")
                policy_style = "green" if chain.policy == "accept" else "red"
                text.append(chain.policy, style=f"bold {policy_style}")
                text.append("\n")

            # Device (for netdev)
            if chain.device:
                text.append("Device: ", style="dim")
                text.append(chain.device, style="blue")
                text.append("\n")
        else:
            text.append("Type: ", style="dim")
            text.append("regular chain", style="dim italic")
            text.append("\n")

        # Rule count
        text.append("\nRules: ", style="dim")
        text.append(str(len(chain.rules)), style="bold")

        return text


class TableInfoPanel(Static):
    """Panel displaying table information."""

    def __init__(
        self,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the table info panel."""
        super().__init__(id=id, classes=classes)
        self._table = None

    def set_table(self, table) -> None:
        """Set the table to display."""
        self._table = table
        self.refresh()

    def render(self) -> Text:
        """Render the table info panel."""
        if not self._table:
            return Text("Select a table to view details", style="dim italic")

        table = self._table
        text = Text()

        # Table name
        text.append("Table: ", style="dim")
        text.append(table.name, style="bold white")
        text.append("\n")

        # Family
        text.append("Family: ", style="dim")
        family_colors = {
            "ip": "green",
            "ip6": "blue",
            "inet": "cyan",
            "arp": "yellow",
            "bridge": "magenta",
            "netdev": "red",
        }
        color = family_colors.get(table.family, "white")
        text.append(table.family, style=f"bold {color}")
        text.append("\n")

        # Handle
        text.append("Handle: ", style="dim")
        text.append(str(table.handle), style="white")
        text.append("\n")

        # Flags
        if table.flags:
            text.append("Flags: ", style="dim")
            text.append(", ".join(table.flags), style="yellow")
            text.append("\n")

        # Statistics
        text.append("\nChains: ", style="dim")
        text.append(str(len(table.chains)), style="bold")
        text.append("\n")

        text.append("Sets: ", style="dim")
        text.append(str(len(table.sets)), style="bold")
        text.append("\n")

        total_rules = sum(len(c.rules) for c in table.chains)
        text.append("Total Rules: ", style="dim")
        text.append(str(total_rules), style="bold")

        return text
