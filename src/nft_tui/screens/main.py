"""Main screen for nft-tui."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual import on, work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, Static, TabbedContent, TabPane

from ..nft.client import NFTClient, NFTError
from ..nft.models import Chain, RuleSet, Set, Table
from ..utils.backup import BackupManager
from ..widgets.counters import ChainInfoPanel, CounterDisplay, TableInfoPanel
from ..widgets.dialogs import (
    AddChainDialog,
    AddRuleDialog,
    AddSetDialog,
    AddTableDialog,
    ConfirmDialog,
    ExportDialog,
    ImportDialog,
    SearchDialog,
)
from ..widgets.table_view import RuleTable, SetElementTable
from ..widgets.tree_view import RulesetTree

if TYPE_CHECKING:
    from pathlib import Path


class MainScreen(Screen):
    """Main application screen."""

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("?", "help", "Help"),
        ("a", "add", "Add"),
        ("d", "delete", "Delete"),
        ("e", "edit", "Edit"),
        ("f", "flush", "Flush"),
        ("r", "refresh", "Refresh"),
        ("i", "import_file", "Import"),
        ("x", "export_file", "Export"),
        ("u", "undo", "Undo"),
        ("t", "conntrack", "Conntrack"),
        ("slash", "search", "Search"),
        ("ctrl+p", "command_palette", "Commands"),
    ]

    def __init__(
        self,
        nft_client: NFTClient,
        backup_manager: BackupManager,
    ) -> None:
        """Initialize the main screen."""
        super().__init__()
        self._client = nft_client
        self._backup = backup_manager
        self._ruleset: RuleSet | None = None
        self._selected_table: Table | None = None
        self._selected_chain: Chain | None = None
        self._selected_set: Set | None = None

    def compose(self) -> ComposeResult:
        """Compose the main screen."""
        yield Header()

        with Horizontal(classes="main-container"):
            # Left panel - Tree view
            with Vertical(classes="tree-panel"):
                yield RulesetTree(label="Loading...", id="ruleset-tree")

            # Right panel - Details
            with Vertical(classes="detail-panel"):
                # Info panel at top
                yield TableInfoPanel(id="table-info", classes="info-panel")
                yield ChainInfoPanel(id="chain-info", classes="info-panel hidden")

                # Tabbed content for rules/sets
                with TabbedContent(id="detail-tabs"):
                    with TabPane("Rules", id="rules-tab"):
                        yield RuleTable(id="rule-table")

                    with TabPane("Sets", id="sets-tab"):
                        yield SetElementTable(id="set-table")

                # Counter display at bottom
                yield CounterDisplay(id="counter-display", classes="counter-panel")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize when mounted."""
        self.load_ruleset()

    @work(exclusive=True)
    async def load_ruleset(self) -> None:
        """Load the nftables ruleset (spawns a worker)."""
        await self._do_load_ruleset()

    async def _do_load_ruleset(self, silent: bool = False) -> None:
        """Internal method to load the ruleset."""
        try:
            self._ruleset = await self._client.list_ruleset_async()

            tree = self.query_one("#ruleset-tree", RulesetTree)
            tree.load_ruleset(self._ruleset)

            # Update counter display
            counter = self.query_one("#counter-display", CounterDisplay)
            counter.update_from_ruleset(self._ruleset)

            # Refresh current view if a chain/table is selected
            self._refresh_current_view()

            if not silent:
                self.notify(
                    f"Loaded {len(self._ruleset.tables)} tables, "
                    f"{self._ruleset.total_chains()} chains, "
                    f"{self._ruleset.total_rules()} rules",
                    severity="information",
                )

        except NFTError as e:
            self.notify(f"Failed to load ruleset: {e}", severity="error")

    def _refresh_current_view(self) -> None:
        """Refresh the current view (rule table or set table) after reload."""
        if not self._ruleset:
            return

        # If a chain is selected, refresh the rules table
        if self._selected_chain and self._selected_table:
            # Find the updated chain in the new ruleset
            updated_chain = self._ruleset.get_chain(
                self._selected_chain.family,
                self._selected_chain.table,
                self._selected_chain.name,
            )
            if updated_chain:
                # Find the updated table too
                updated_table = self._ruleset.get_table(
                    self._selected_table.family,
                    self._selected_table.name,
                )
                if updated_table:
                    self._selected_chain = updated_chain
                    self._selected_table = updated_table

                    # Reload the rules table
                    rule_table = self.query_one("#rule-table", RuleTable)
                    rule_table.load_chain(updated_chain, updated_table)

                    # Update chain info panel
                    chain_info = self.query_one("#chain-info", ChainInfoPanel)
                    chain_info.set_chain(updated_chain)

                    # Update counter display for chain
                    counter = self.query_one("#counter-display", CounterDisplay)
                    counter.update_from_chain(updated_chain)

    @on(RulesetTree.TableSelected)
    def on_table_selected(self, event: RulesetTree.TableSelected) -> None:
        """Handle table selection."""
        self._selected_table = event.table
        self._selected_chain = None
        self._selected_set = None

        # Update info panel
        table_info = self.query_one("#table-info", TableInfoPanel)
        table_info.set_table(event.table)
        table_info.remove_class("hidden")

        chain_info = self.query_one("#chain-info", ChainInfoPanel)
        chain_info.add_class("hidden")

        # Clear rule table
        rule_table = self.query_one("#rule-table", RuleTable)
        rule_table.clear()

    @on(RulesetTree.ChainSelected)
    def on_chain_selected(self, event: RulesetTree.ChainSelected) -> None:
        """Handle chain selection."""
        self._selected_table = event.table
        self._selected_chain = event.chain
        self._selected_set = None

        # Update info panels
        table_info = self.query_one("#table-info", TableInfoPanel)
        table_info.add_class("hidden")

        chain_info = self.query_one("#chain-info", ChainInfoPanel)
        chain_info.set_chain(event.chain)
        chain_info.remove_class("hidden")

        # Switch to rules tab FIRST
        tabs = self.query_one("#detail-tabs", TabbedContent)
        tabs.active = "rules-tab"

        # Load rules into table
        rule_table = self.query_one("#rule-table", RuleTable)
        rule_table.load_chain(event.chain, event.table)

        # Update counter display
        counter = self.query_one("#counter-display", CounterDisplay)
        counter.update_from_chain(event.chain)

    @on(RulesetTree.SetSelected)
    def on_set_selected(self, event: RulesetTree.SetSelected) -> None:
        """Handle set selection."""
        self._selected_table = event.table
        self._selected_chain = None
        self._selected_set = event.nft_set

        # Load set elements
        set_table = self.query_one("#set-table", SetElementTable)
        set_table.load_set(event.nft_set)

        # Switch to sets tab
        tabs = self.query_one("#detail-tabs", TabbedContent)
        tabs.active = "sets-tab"

    def action_quit(self) -> None:
        """Quit the application."""
        self.app.exit()

    def action_help(self) -> None:
        """Show help screen."""
        from .help import HelpScreen

        self.app.push_screen(HelpScreen())

    def action_refresh(self) -> None:
        """Refresh the ruleset."""
        self.load_ruleset()

    def action_conntrack(self) -> None:
        """Show connection tracking screen."""
        from .conntrack import ConntrackScreen

        self.app.push_screen(ConntrackScreen())

    @work
    async def action_add(self) -> None:
        """Add a new item based on context."""
        tree = self.query_one("#ruleset-tree", RulesetTree)

        if self._selected_chain:
            # Add rule to chain
            result = await self.app.push_screen_wait(
                AddRuleDialog(
                    self._selected_chain.family,
                    self._selected_chain.table,
                    self._selected_chain.name,
                )
            )
            if result:
                await self._add_rule(result)

        elif self._selected_table:
            # Add chain to table
            result = await self.app.push_screen_wait(
                AddChainDialog(self._selected_table.family, self._selected_table.name)
            )
            if result:
                await self._add_chain(result)

        else:
            # Add new table
            result = await self.app.push_screen_wait(AddTableDialog())
            if result:
                family, name = result
                await self._add_table(family, name)

    async def _add_table(self, family: str, name: str) -> None:
        """Add a new table."""
        try:
            await self._backup.create_auto_backup_async(self._client)
            await self._client.add_table_async(family, name)
            self.notify(f"Table {family}::{name} created", severity="information")
            await self._do_load_ruleset(silent=True)
        except NFTError as e:
            self.notify(f"Failed to create table: {e}", severity="error")

    async def _add_chain(self, chain_data: dict) -> None:
        """Add a new chain."""
        try:
            await self._backup.create_auto_backup_async(self._client)
            await self._client.add_chain_async(
                chain_data["family"],
                chain_data["table"],
                chain_data["name"],
                chain_type=chain_data.get("type"),
                hook=chain_data.get("hook"),
                priority=chain_data.get("priority"),
                policy=chain_data.get("policy"),
            )
            self.notify(
                f"Chain {chain_data['name']} created",
                severity="information",
            )
            await self._do_load_ruleset(silent=True)
        except NFTError as e:
            self.notify(f"Failed to create chain: {e}", severity="error")

    async def _add_rule(self, rule_spec: str) -> None:
        """Add a new rule."""
        if not self._selected_chain:
            return

        try:
            await self._backup.create_auto_backup_async(self._client)
            await self._client.add_rule_async(
                self._selected_chain.family,
                self._selected_chain.table,
                self._selected_chain.name,
                rule_spec,
            )
            self.notify("Rule added", severity="information")
            await self._do_load_ruleset(silent=True)
        except NFTError as e:
            self.notify(f"Failed to add rule: {e}", severity="error")

    @work
    async def action_delete(self) -> None:
        """Delete the selected item."""
        rule_table = self.query_one("#rule-table", RuleTable)
        selected_rule = rule_table.get_selected_rule()

        if selected_rule and self._selected_chain and self._selected_table:
            # Delete rule
            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(
                    title="Delete Rule",
                    message=f"Delete rule with handle {selected_rule.handle}?",
                    confirm_label="Delete",
                    destructive=True,
                )
            )
            if confirmed:
                await self._delete_rule(selected_rule.handle)

        elif self._selected_chain and self._selected_table:
            # Delete chain
            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(
                    title="Delete Chain",
                    message=f"Delete chain '{self._selected_chain.name}'?",
                    confirm_label="Delete",
                    destructive=True,
                )
            )
            if confirmed:
                await self._delete_chain()

        elif self._selected_table:
            # Delete table
            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(
                    title="Delete Table",
                    message=f"Delete table '{self._selected_table.full_name}'?",
                    confirm_label="Delete",
                    destructive=True,
                )
            )
            if confirmed:
                await self._delete_table()

    async def _delete_rule(self, handle: int) -> None:
        """Delete a rule by handle."""
        if not self._selected_chain:
            return

        try:
            await self._backup.create_auto_backup_async(self._client)
            await self._client.delete_rule_async(
                self._selected_chain.family,
                self._selected_chain.table,
                self._selected_chain.name,
                handle,
            )
            self.notify("Rule deleted", severity="information")
            await self._do_load_ruleset(silent=True)
        except NFTError as e:
            self.notify(f"Failed to delete rule: {e}", severity="error")

    async def _delete_chain(self) -> None:
        """Delete the selected chain."""
        if not self._selected_chain:
            return

        try:
            await self._backup.create_auto_backup_async(self._client)
            await self._client.delete_chain_async(
                self._selected_chain.family,
                self._selected_chain.table,
                self._selected_chain.name,
            )
            self.notify("Chain deleted", severity="information")
            self._selected_chain = None
            await self._do_load_ruleset(silent=True)
        except NFTError as e:
            self.notify(f"Failed to delete chain: {e}", severity="error")

    async def _delete_table(self) -> None:
        """Delete the selected table."""
        if not self._selected_table:
            return

        try:
            await self._backup.create_auto_backup_async(self._client)
            await self._client.delete_table_async(
                self._selected_table.family,
                self._selected_table.name,
            )
            self.notify("Table deleted", severity="information")
            self._selected_table = None
            await self._do_load_ruleset(silent=True)
        except NFTError as e:
            self.notify(f"Failed to delete table: {e}", severity="error")

    @work
    async def action_flush(self) -> None:
        """Flush rules from chain or table."""
        if self._selected_chain:
            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(
                    title="Flush Chain",
                    message=f"Remove all rules from chain '{self._selected_chain.name}'?",
                    confirm_label="Flush",
                    destructive=True,
                )
            )
            if confirmed:
                await self._flush_chain()

        elif self._selected_table:
            confirmed = await self.app.push_screen_wait(
                ConfirmDialog(
                    title="Flush Table",
                    message=f"Remove all rules from table '{self._selected_table.full_name}'?",
                    confirm_label="Flush",
                    destructive=True,
                )
            )
            if confirmed:
                await self._flush_table()

    async def _flush_chain(self) -> None:
        """Flush the selected chain."""
        if not self._selected_chain:
            return

        try:
            await self._backup.create_auto_backup_async(self._client)
            await self._client.flush_chain_async(
                self._selected_chain.family,
                self._selected_chain.table,
                self._selected_chain.name,
            )
            self.notify("Chain flushed", severity="information")
            await self._do_load_ruleset(silent=True)
        except NFTError as e:
            self.notify(f"Failed to flush chain: {e}", severity="error")

    async def _flush_table(self) -> None:
        """Flush the selected table."""
        if not self._selected_table:
            return

        try:
            await self._backup.create_auto_backup_async(self._client)
            await self._client.flush_table_async(
                self._selected_table.family,
                self._selected_table.name,
            )
            self.notify("Table flushed", severity="information")
            await self._do_load_ruleset(silent=True)
        except NFTError as e:
            self.notify(f"Failed to flush table: {e}", severity="error")

    @work
    async def action_import_file(self) -> None:
        """Import a ruleset file."""
        path = await self.app.push_screen_wait(ImportDialog())
        if path:
            await self._import_file(path)

    async def _import_file(self, path: Path) -> None:
        """Import a ruleset file."""
        try:
            await self._backup.create_auto_backup_async(self._client)
            await self._client.import_file_async(path)
            self.notify(f"Imported {path.name}", severity="information")
            await self._do_load_ruleset(silent=True)
        except NFTError as e:
            self.notify(f"Failed to import: {e}", severity="error")

    @work
    async def action_export_file(self) -> None:
        """Export the ruleset to a file."""
        path = await self.app.push_screen_wait(ExportDialog())
        if path:
            await self._export_file(path)

    async def _export_file(self, path: Path) -> None:
        """Export the ruleset to a file."""
        try:
            content = await self._client.export_ruleset_async()
            path.write_text(content)
            self.notify(f"Exported to {path}", severity="information")
        except Exception as e:
            self.notify(f"Failed to export: {e}", severity="error")

    @work
    async def action_undo(self) -> None:
        """Restore from the last backup."""
        backups = self._backup.list_backups()
        if not backups:
            self.notify("No backups available", severity="warning")
            return

        latest = backups[0]
        confirmed = await self.app.push_screen_wait(
            ConfirmDialog(
                title="Restore Backup",
                message=f"Restore from backup created at {latest[1].strftime('%Y-%m-%d %H:%M:%S')}?",
                confirm_label="Restore",
                destructive=True,
            )
        )
        if confirmed:
            await self._restore_backup(latest[0])

    async def _restore_backup(self, path: Path) -> None:
        """Restore from a backup."""
        try:
            await self._backup.restore_backup_async(self._client, path)
            self.notify("Backup restored", severity="information")
            await self._do_load_ruleset(silent=True)
        except Exception as e:
            self.notify(f"Failed to restore: {e}", severity="error")

    @work
    async def action_search(self) -> None:
        """Open search dialog."""
        term = await self.app.push_screen_wait(SearchDialog())
        if term:
            self._search_rules(term)

    def _search_rules(self, term: str) -> None:
        """Search for rules containing the term."""
        if not self._ruleset:
            return

        results = []
        term_lower = term.lower()

        for table in self._ruleset.tables:
            for chain in table.chains:
                for rule in chain.rules:
                    rule_text = rule.format_expr().lower()
                    if term_lower in rule_text:
                        results.append((table, chain, rule))

        if results:
            self.notify(f"Found {len(results)} matching rules", severity="information")
            # Select the first result
            table, chain, rule = results[0]
            self._selected_table = table
            self._selected_chain = chain

            # Update UI
            chain_info = self.query_one("#chain-info", ChainInfoPanel)
            chain_info.set_chain(chain)
            chain_info.remove_class("hidden")

            rule_table = self.query_one("#rule-table", RuleTable)
            rule_table.load_chain(chain, table)
        else:
            self.notify(f"No rules matching '{term}'", severity="warning")

    def action_command_palette(self) -> None:
        """Open the command palette."""
        self.app.action_command_palette()

    def action_edit(self) -> None:
        """Edit the selected item."""
        self.notify("Edit not yet implemented", severity="warning")
