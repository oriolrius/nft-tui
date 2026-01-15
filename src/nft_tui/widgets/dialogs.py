"""Modal dialog widgets for nft-tui."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from textual import on
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Select, Static, TextArea

if TYPE_CHECKING:
    pass


class ConfirmDialog(ModalScreen[bool]):
    """A confirmation dialog."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("y", "confirm", "Yes"),
        ("n", "cancel", "No"),
    ]

    def __init__(
        self,
        title: str = "Confirm",
        message: str = "Are you sure?",
        confirm_label: str = "Yes",
        cancel_label: str = "No",
        destructive: bool = False,
    ) -> None:
        """Initialize the confirmation dialog."""
        super().__init__()
        self._title = title
        self._message = message
        self._confirm_label = confirm_label
        self._cancel_label = cancel_label
        self._destructive = destructive

    def compose(self) -> ComposeResult:
        """Compose the dialog."""
        with Vertical(classes="dialog-container"):
            yield Label(self._title, classes="dialog-title")
            yield Static(self._message, classes="dialog-message")
            with Horizontal(classes="dialog-buttons"):
                yield Button(
                    self._cancel_label,
                    variant="default",
                    id="cancel-btn",
                )
                yield Button(
                    self._confirm_label,
                    variant="error" if self._destructive else "primary",
                    id="confirm-btn",
                )

    def action_confirm(self) -> None:
        """Confirm the action."""
        self.dismiss(True)

    def action_cancel(self) -> None:
        """Cancel the action."""
        self.dismiss(False)

    @on(Button.Pressed, "#confirm-btn")
    def on_confirm(self) -> None:
        """Handle confirm button press."""
        self.dismiss(True)

    @on(Button.Pressed, "#cancel-btn")
    def on_cancel(self) -> None:
        """Handle cancel button press."""
        self.dismiss(False)


class AddTableDialog(ModalScreen[tuple[str, str] | None]):
    """Dialog for adding a new table."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    FAMILIES = [
        ("ip", "ip - IPv4"),
        ("ip6", "ip6 - IPv6"),
        ("inet", "inet - IPv4/IPv6"),
        ("arp", "arp - ARP"),
        ("bridge", "bridge - Bridge"),
        ("netdev", "netdev - Network Device"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the dialog."""
        with Vertical(classes="dialog-container"):
            yield Label("Add Table", classes="dialog-title")

            yield Label("Family:", classes="input-label")
            yield Select(
                [(label, value) for value, label in self.FAMILIES],
                value="inet",
                id="family-select",
            )

            yield Label("Table Name:", classes="input-label")
            yield Input(placeholder="e.g., filter, nat, mangle", id="name-input")

            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", variant="default", id="cancel-btn")
                yield Button("Add Table", variant="primary", id="add-btn")

    @on(Button.Pressed, "#cancel-btn")
    def on_cancel(self) -> None:
        """Handle cancel button press."""
        self.dismiss(None)

    @on(Button.Pressed, "#add-btn")
    def on_add(self) -> None:
        """Handle add button press."""
        family_select = self.query_one("#family-select", Select)
        name_input = self.query_one("#name-input", Input)

        family = str(family_select.value)
        name = name_input.value.strip()

        if name:
            self.dismiss((family, name))
        else:
            name_input.focus()

    def action_cancel(self) -> None:
        """Cancel the dialog."""
        self.dismiss(None)


class AddChainDialog(ModalScreen[dict | None]):
    """Dialog for adding a new chain."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    CHAIN_TYPES = [
        ("", "(none - regular chain)"),
        ("filter", "filter"),
        ("nat", "nat"),
        ("route", "route"),
    ]

    HOOKS = [
        ("", "(none)"),
        ("prerouting", "prerouting"),
        ("input", "input"),
        ("forward", "forward"),
        ("output", "output"),
        ("postrouting", "postrouting"),
        ("ingress", "ingress"),
        ("egress", "egress"),
    ]

    POLICIES = [
        ("accept", "accept"),
        ("drop", "drop"),
    ]

    def __init__(self, family: str, table: str) -> None:
        """Initialize the dialog."""
        super().__init__()
        self._family = family
        self._table = table

    def compose(self) -> ComposeResult:
        """Compose the dialog."""
        with Vertical(classes="dialog-container"):
            yield Label(f"Add Chain to {self._family}::{self._table}", classes="dialog-title")

            yield Label("Chain Name:", classes="input-label")
            yield Input(placeholder="e.g., input, output, forward", id="name-input")

            yield Label("Type (for base chains):", classes="input-label")
            yield Select(
                [(label, value) for value, label in self.CHAIN_TYPES],
                value="",
                id="type-select",
            )

            yield Label("Hook:", classes="input-label")
            yield Select(
                [(label, value) for value, label in self.HOOKS],
                value="",
                id="hook-select",
            )

            yield Label("Priority:", classes="input-label")
            yield Input(value="0", placeholder="e.g., 0, -100, 50", id="priority-input")

            yield Label("Policy:", classes="input-label")
            yield Select(
                [(label, value) for value, label in self.POLICIES],
                value="accept",
                id="policy-select",
            )

            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", variant="default", id="cancel-btn")
                yield Button("Add Chain", variant="primary", id="add-btn")

    @on(Button.Pressed, "#cancel-btn")
    def on_cancel(self) -> None:
        """Handle cancel button press."""
        self.dismiss(None)

    @on(Button.Pressed, "#add-btn")
    def on_add(self) -> None:
        """Handle add button press."""
        name = self.query_one("#name-input", Input).value.strip()
        chain_type = str(self.query_one("#type-select", Select).value)
        hook = str(self.query_one("#hook-select", Select).value)
        priority_str = self.query_one("#priority-input", Input).value.strip()
        policy = str(self.query_one("#policy-select", Select).value)

        if not name:
            self.query_one("#name-input", Input).focus()
            return

        try:
            priority = int(priority_str) if priority_str else 0
        except ValueError:
            self.query_one("#priority-input", Input).focus()
            return

        result = {
            "family": self._family,
            "table": self._table,
            "name": name,
            "type": chain_type if chain_type else None,
            "hook": hook if hook else None,
            "priority": priority if chain_type else None,
            "policy": policy if chain_type else None,
        }

        self.dismiss(result)

    def action_cancel(self) -> None:
        """Cancel the dialog."""
        self.dismiss(None)


class AddRuleDialog(ModalScreen[str | None]):
    """Dialog for adding a new rule."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("ctrl+s", "submit", "Add"),
    ]

    def __init__(self, family: str, table: str, chain: str) -> None:
        """Initialize the dialog."""
        super().__init__()
        self._family = family
        self._table = table
        self._chain = chain

    def compose(self) -> ComposeResult:
        """Compose the dialog."""
        with Vertical(classes="dialog-container dialog-wide"):
            yield Label(
                f"Add Rule to {self._family}::{self._table}::{self._chain}",
                classes="dialog-title",
            )

            yield Label("Rule specification:", classes="input-label")
            yield Static(
                "Examples: tcp dport 22 accept, ip saddr 10.0.0.0/8 drop",
                classes="dialog-hint",
            )
            yield TextArea(
                "",
                language="shell",
                theme="monokai",
                id="rule-input",
                classes="rule-textarea",
            )

            yield Static("", id="validation-status", classes="validation-status")

            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", variant="default", id="cancel-btn")
                yield Button("Add Rule", variant="primary", id="add-btn")

    def on_mount(self) -> None:
        """Focus the rule input on mount."""
        self.query_one("#rule-input", TextArea).focus()

    @on(Button.Pressed, "#cancel-btn")
    def on_cancel(self) -> None:
        """Handle cancel button press."""
        self.dismiss(None)

    @on(Button.Pressed, "#add-btn")
    def on_add(self) -> None:
        """Handle add button press."""
        rule_spec = self.query_one("#rule-input", TextArea).text.strip()
        if rule_spec:
            self.dismiss(rule_spec)
        else:
            self.query_one("#rule-input", TextArea).focus()

    def action_cancel(self) -> None:
        """Cancel the dialog."""
        self.dismiss(None)

    def action_submit(self) -> None:
        """Submit the rule."""
        rule_spec = self.query_one("#rule-input", TextArea).text.strip()
        if rule_spec:
            self.dismiss(rule_spec)

    def show_validation_error(self, error: str) -> None:
        """Show a validation error."""
        status = self.query_one("#validation-status", Static)
        status.update(f"[red bold]Error:[/] {error}")

    def clear_validation(self) -> None:
        """Clear validation status."""
        status = self.query_one("#validation-status", Static)
        status.update("")


class AddSetDialog(ModalScreen[dict | None]):
    """Dialog for adding a new set."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    SET_TYPES = [
        ("ipv4_addr", "IPv4 Address"),
        ("ipv6_addr", "IPv6 Address"),
        ("ether_addr", "MAC Address"),
        ("inet_proto", "Protocol"),
        ("inet_service", "Port"),
        ("mark", "Mark"),
        ("ifname", "Interface Name"),
    ]

    SET_FLAGS = [
        ("constant", "Constant"),
        ("dynamic", "Dynamic"),
        ("interval", "Interval"),
        ("timeout", "Timeout"),
    ]

    def __init__(self, family: str, table: str) -> None:
        """Initialize the dialog."""
        super().__init__()
        self._family = family
        self._table = table

    def compose(self) -> ComposeResult:
        """Compose the dialog."""
        with Vertical(classes="dialog-container"):
            yield Label(f"Add Set to {self._family}::{self._table}", classes="dialog-title")

            yield Label("Set Name:", classes="input-label")
            yield Input(placeholder="e.g., allowed_ips, blocked_ports", id="name-input")

            yield Label("Element Type:", classes="input-label")
            yield Select(
                [(label, value) for value, label in self.SET_TYPES],
                value="ipv4_addr",
                id="type-select",
            )

            yield Label("Timeout (seconds, optional):", classes="input-label")
            yield Input(placeholder="e.g., 3600", id="timeout-input")

            yield Label("Comment (optional):", classes="input-label")
            yield Input(placeholder="Description of the set", id="comment-input")

            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", variant="default", id="cancel-btn")
                yield Button("Add Set", variant="primary", id="add-btn")

    @on(Button.Pressed, "#cancel-btn")
    def on_cancel(self) -> None:
        """Handle cancel button press."""
        self.dismiss(None)

    @on(Button.Pressed, "#add-btn")
    def on_add(self) -> None:
        """Handle add button press."""
        name = self.query_one("#name-input", Input).value.strip()
        set_type = str(self.query_one("#type-select", Select).value)
        timeout_str = self.query_one("#timeout-input", Input).value.strip()
        comment = self.query_one("#comment-input", Input).value.strip()

        if not name:
            self.query_one("#name-input", Input).focus()
            return

        timeout = None
        if timeout_str:
            try:
                timeout = int(timeout_str)
            except ValueError:
                self.query_one("#timeout-input", Input).focus()
                return

        result = {
            "family": self._family,
            "table": self._table,
            "name": name,
            "type": set_type,
            "timeout": timeout,
            "comment": comment if comment else None,
        }

        self.dismiss(result)

    def action_cancel(self) -> None:
        """Cancel the dialog."""
        self.dismiss(None)


class ImportDialog(ModalScreen[Path | None]):
    """Dialog for importing a ruleset file."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the dialog."""
        with Vertical(classes="dialog-container"):
            yield Label("Import Ruleset", classes="dialog-title")

            yield Label("File path:", classes="input-label")
            yield Input(
                placeholder="/path/to/ruleset.nft",
                id="path-input",
            )

            yield Static(
                "Enter the full path to an nftables ruleset file.",
                classes="dialog-hint",
            )

            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", variant="default", id="cancel-btn")
                yield Button("Import", variant="primary", id="import-btn")

    @on(Button.Pressed, "#cancel-btn")
    def on_cancel(self) -> None:
        """Handle cancel button press."""
        self.dismiss(None)

    @on(Button.Pressed, "#import-btn")
    def on_import(self) -> None:
        """Handle import button press."""
        path_str = self.query_one("#path-input", Input).value.strip()

        if not path_str:
            self.query_one("#path-input", Input).focus()
            return

        path = Path(path_str).expanduser()
        if path.exists():
            self.dismiss(path)
        else:
            self.notify(f"File not found: {path}", severity="error")
            self.query_one("#path-input", Input).focus()

    def action_cancel(self) -> None:
        """Cancel the dialog."""
        self.dismiss(None)


class ExportDialog(ModalScreen[Path | None]):
    """Dialog for exporting a ruleset file."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the dialog."""
        with Vertical(classes="dialog-container"):
            yield Label("Export Ruleset", classes="dialog-title")

            yield Label("File path:", classes="input-label")
            yield Input(
                value=str(Path.home() / "ruleset.nft"),
                id="path-input",
            )

            yield Static(
                "The current ruleset will be exported to this file.",
                classes="dialog-hint",
            )

            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", variant="default", id="cancel-btn")
                yield Button("Export", variant="primary", id="export-btn")

    @on(Button.Pressed, "#cancel-btn")
    def on_cancel(self) -> None:
        """Handle cancel button press."""
        self.dismiss(None)

    @on(Button.Pressed, "#export-btn")
    def on_export(self) -> None:
        """Handle export button press."""
        path_str = self.query_one("#path-input", Input).value.strip()

        if not path_str:
            self.query_one("#path-input", Input).focus()
            return

        path = Path(path_str).expanduser()
        self.dismiss(path)

    def action_cancel(self) -> None:
        """Cancel the dialog."""
        self.dismiss(None)


class BackupDialog(ModalScreen[Path | None]):
    """Dialog for selecting a backup to restore."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(self, backups: list[tuple[Path, str, str]]) -> None:
        """Initialize the dialog.

        Args:
            backups: List of (path, date_str, size_str) tuples.
        """
        super().__init__()
        self._backups = backups

    def compose(self) -> ComposeResult:
        """Compose the dialog."""
        with Vertical(classes="dialog-container dialog-wide"):
            yield Label("Restore Backup", classes="dialog-title")

            if self._backups:
                options = [
                    (f"{date} ({size})", path)
                    for path, date, size in self._backups
                ]
                yield Select(options, id="backup-select")
            else:
                yield Static("No backups available", classes="dialog-hint")

            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", variant="default", id="cancel-btn")
                if self._backups:
                    yield Button("Restore", variant="warning", id="restore-btn")

    @on(Button.Pressed, "#cancel-btn")
    def on_cancel(self) -> None:
        """Handle cancel button press."""
        self.dismiss(None)

    @on(Button.Pressed, "#restore-btn")
    def on_restore(self) -> None:
        """Handle restore button press."""
        select = self.query_one("#backup-select", Select)
        if select.value and select.value != Select.BLANK:
            self.dismiss(select.value)

    def action_cancel(self) -> None:
        """Cancel the dialog."""
        self.dismiss(None)


class SearchDialog(ModalScreen[str | None]):
    """Dialog for searching rules."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the dialog."""
        with Vertical(classes="dialog-container"):
            yield Label("Search Rules", classes="dialog-title")

            yield Label("Search term:", classes="input-label")
            yield Input(
                placeholder="e.g., dport 22, accept, 192.168",
                id="search-input",
            )

            yield Static(
                "Search through all rule expressions",
                classes="dialog-hint",
            )

            with Horizontal(classes="dialog-buttons"):
                yield Button("Cancel", variant="default", id="cancel-btn")
                yield Button("Search", variant="primary", id="search-btn")

    def on_mount(self) -> None:
        """Focus the search input on mount."""
        self.query_one("#search-input", Input).focus()

    @on(Button.Pressed, "#cancel-btn")
    def on_cancel(self) -> None:
        """Handle cancel button press."""
        self.dismiss(None)

    @on(Button.Pressed, "#search-btn")
    def on_search(self) -> None:
        """Handle search button press."""
        term = self.query_one("#search-input", Input).value.strip()
        self.dismiss(term if term else None)

    @on(Input.Submitted, "#search-input")
    def on_input_submitted(self) -> None:
        """Handle enter in search input."""
        term = self.query_one("#search-input", Input).value.strip()
        self.dismiss(term if term else None)

    def action_cancel(self) -> None:
        """Cancel the dialog."""
        self.dismiss(None)
