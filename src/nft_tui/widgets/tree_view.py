"""Tree view widget for navigating the nftables ruleset."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual.message import Message
from textual.widgets import Tree
from textual.widgets.tree import TreeNode

if TYPE_CHECKING:
    from ..nft.models import Chain, RuleSet, Set, Table


class RulesetTree(Tree[str]):
    """Tree widget for displaying and navigating the nftables ruleset."""

    BINDINGS = [
        ("j", "cursor_down", "Down"),
        ("k", "cursor_up", "Up"),
        ("l", "expand", "Expand"),
        ("h", "collapse", "Collapse"),
        ("enter", "select_cursor", "Select"),
        ("space", "toggle_expand", "Toggle"),
    ]

    class TableSelected(Message):
        """Message sent when a table is selected."""

        def __init__(self, table: Table) -> None:
            super().__init__()
            self.table = table

    class ChainSelected(Message):
        """Message sent when a chain is selected."""

        def __init__(self, chain: Chain, table: Table) -> None:
            super().__init__()
            self.chain = chain
            self.table = table

    class SetSelected(Message):
        """Message sent when a set is selected."""

        def __init__(self, nft_set: Set, table: Table) -> None:
            super().__init__()
            self.nft_set = nft_set
            self.table = table

    class RootSelected(Message):
        """Message sent when root is selected."""

        def __init__(self) -> None:
            super().__init__()

    def __init__(
        self,
        label: str = "Ruleset",
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the tree."""
        super().__init__(label, id=id, classes=classes)
        self._tables: dict[str, Table] = {}
        self._chains: dict[str, Chain] = {}
        self._sets: dict[str, Set] = {}

    def load_ruleset(self, ruleset: RuleSet) -> None:
        """Load a ruleset into the tree."""
        self.clear()
        self._tables.clear()
        self._chains.clear()
        self._sets.clear()

        # Update root label with version info
        version = ruleset.version
        self.root.set_label(Text(f"Ruleset (nft {version})", style="bold cyan"))
        self.root.expand()

        for table in ruleset.tables:
            self._add_table_node(self.root, table)

    def _add_table_node(self, parent: TreeNode[str], table: Table) -> None:
        """Add a table node to the tree."""
        # Create table label with family and name
        label = self._format_table_label(table)
        table_key = f"table:{table.family}:{table.name}"
        self._tables[table_key] = table

        table_node = parent.add(label, data=table_key, expand=True)

        # Add chains
        if table.chains:
            for chain in table.chains:
                self._add_chain_node(table_node, chain, table)

        # Add sets section if there are sets
        if table.sets:
            sets_label = Text("Sets", style="dim italic")
            sets_node = table_node.add(sets_label, data=f"sets:{table.family}:{table.name}")

            for nft_set in table.sets:
                self._add_set_node(sets_node, nft_set, table)

    def _add_chain_node(
        self, parent: TreeNode[str], chain: Chain, table: Table
    ) -> None:
        """Add a chain node to the tree."""
        label = self._format_chain_label(chain)
        chain_key = f"chain:{chain.family}:{chain.table}:{chain.name}"
        self._chains[chain_key] = chain

        chain_node = parent.add(label, data=chain_key, allow_expand=False)

        # Add rule count badge
        rule_count = len(chain.rules)
        if rule_count > 0:
            chain_node.set_label(
                Text.assemble(
                    self._format_chain_label(chain),
                    " ",
                    Text(f"({rule_count})", style="dim"),
                )
            )

    def _add_set_node(
        self, parent: TreeNode[str], nft_set: Set, table: Table
    ) -> None:
        """Add a set node to the tree."""
        label = self._format_set_label(nft_set)
        set_key = f"set:{nft_set.family}:{nft_set.table}:{nft_set.name}"
        self._sets[set_key] = nft_set

        parent.add(label, data=set_key, allow_expand=False)

    def _format_table_label(self, table: Table) -> Text:
        """Format a table label with styling."""
        family_colors = {
            "ip": "green",
            "ip6": "blue",
            "inet": "cyan",
            "arp": "yellow",
            "bridge": "magenta",
            "netdev": "red",
        }
        color = family_colors.get(table.family, "white")

        return Text.assemble(
            Text(table.family, style=f"bold {color}"),
            Text("::", style="dim"),
            Text(table.name, style="bold white"),
        )

    def _format_chain_label(self, chain: Chain) -> Text:
        """Format a chain label with styling."""
        parts = [Text(chain.name, style="white")]

        if chain.is_base_chain:
            # Add hook info
            hook_style = "dim cyan"
            if chain.hook in ("input", "prerouting"):
                hook_style = "dim green"
            elif chain.hook in ("output", "postrouting"):
                hook_style = "dim blue"
            elif chain.hook == "forward":
                hook_style = "dim yellow"

            parts.append(Text(f" [{chain.hook}]", style=hook_style))

            # Add policy indicator
            if chain.policy:
                policy_style = "green" if chain.policy == "accept" else "red"
                parts.append(Text(f" {chain.policy}", style=f"dim {policy_style}"))

        return Text.assemble(*parts)

    def _format_set_label(self, nft_set: Set) -> Text:
        """Format a set label with styling."""
        elem_count = len(nft_set.elements)
        type_str = nft_set.type_str

        return Text.assemble(
            Text("@", style="dim yellow"),
            Text(nft_set.name, style="yellow"),
            Text(f" ({type_str})", style="dim"),
            Text(f" [{elem_count}]", style="dim italic") if elem_count else "",
        )

    def action_expand(self) -> None:
        """Expand the current node."""
        if self.cursor_node and self.cursor_node.allow_expand:
            self.cursor_node.expand()
            self.cursor_node.refresh()

    def action_collapse(self) -> None:
        """Collapse the current node."""
        if self.cursor_node:
            if self.cursor_node.is_expanded:
                self.cursor_node.collapse()
            elif self.cursor_node.parent:
                self.cursor_line = self.cursor_node.parent.line

    def action_toggle_expand(self) -> None:
        """Toggle expand/collapse of current node."""
        if self.cursor_node and self.cursor_node.allow_expand:
            self.cursor_node.toggle()

    def on_tree_node_selected(self, event: Tree.NodeSelected[str]) -> None:
        """Handle node selection."""
        data = event.node.data
        if not data:
            self.post_message(self.RootSelected())
            return

        if data.startswith("table:"):
            table = self._tables.get(data)
            if table:
                self.post_message(self.TableSelected(table))
        elif data.startswith("chain:"):
            chain = self._chains.get(data)
            if chain:
                # Find the parent table
                parts = data.split(":")
                table_key = f"table:{parts[1]}:{parts[2]}"
                table = self._tables.get(table_key)
                if table:
                    self.post_message(self.ChainSelected(chain, table))
        elif data.startswith("set:"):
            nft_set = self._sets.get(data)
            if nft_set:
                parts = data.split(":")
                table_key = f"table:{parts[1]}:{parts[2]}"
                table = self._tables.get(table_key)
                if table:
                    self.post_message(self.SetSelected(nft_set, table))

    def get_selected_table(self) -> Table | None:
        """Get the currently selected table, or the table of the selected item."""
        if not self.cursor_node or not self.cursor_node.data:
            return None

        data = self.cursor_node.data

        if data.startswith("table:"):
            return self._tables.get(data)

        if data.startswith("chain:") or data.startswith("set:") or data.startswith("sets:"):
            parts = data.split(":")
            table_key = f"table:{parts[1]}:{parts[2]}"
            return self._tables.get(table_key)

        return None

    def get_selected_chain(self) -> tuple[Chain, Table] | None:
        """Get the currently selected chain and its table."""
        if not self.cursor_node or not self.cursor_node.data:
            return None

        data = self.cursor_node.data

        if data.startswith("chain:"):
            chain = self._chains.get(data)
            if chain:
                parts = data.split(":")
                table_key = f"table:{parts[1]}:{parts[2]}"
                table = self._tables.get(table_key)
                if table:
                    return chain, table

        return None

    def get_selected_set(self) -> tuple[Set, Table] | None:
        """Get the currently selected set and its table."""
        if not self.cursor_node or not self.cursor_node.data:
            return None

        data = self.cursor_node.data

        if data.startswith("set:"):
            nft_set = self._sets.get(data)
            if nft_set:
                parts = data.split(":")
                table_key = f"table:{parts[1]}:{parts[2]}"
                table = self._tables.get(table_key)
                if table:
                    return nft_set, table

        return None

    def refresh_node(self, chain: Chain) -> None:
        """Refresh a chain node to update rule count."""
        chain_key = f"chain:{chain.family}:{chain.table}:{chain.name}"

        def find_and_update(node: TreeNode[str]) -> bool:
            if node.data == chain_key:
                rule_count = len(chain.rules)
                label = self._format_chain_label(chain)
                if rule_count > 0:
                    node.set_label(
                        Text.assemble(
                            label,
                            " ",
                            Text(f"({rule_count})", style="dim"),
                        )
                    )
                else:
                    node.set_label(label)
                return True

            for child in node.children:
                if find_and_update(child):
                    return True

            return False

        find_and_update(self.root)
