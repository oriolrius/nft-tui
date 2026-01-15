"""Main application for nft-tui."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from textual.app import App
from textual.command import CommandPalette, Hit, Hits, Provider

from .nft.client import NFTClient, NFTError
from .screens.main import MainScreen
from .utils.backup import BackupManager

if TYPE_CHECKING:
    pass


class NFTCommandProvider(Provider):
    """Command palette provider for nft-tui commands."""

    async def search(self, query: str) -> Hits:
        """Search for matching commands."""
        commands = [
            ("Refresh Ruleset", "refresh", "Reload the ruleset from nftables"),
            ("Add Table", "add_table", "Create a new table"),
            ("Add Chain", "add_chain", "Create a new chain"),
            ("Add Rule", "add_rule", "Add a new rule to the selected chain"),
            ("Delete Selected", "delete", "Delete the selected item"),
            ("Flush Chain", "flush_chain", "Remove all rules from the selected chain"),
            ("Flush Table", "flush_table", "Remove all rules from the selected table"),
            ("Import Ruleset", "import", "Import rules from a file"),
            ("Export Ruleset", "export", "Export rules to a file"),
            ("Restore Backup", "restore", "Restore from a backup"),
            ("View Conntrack", "conntrack", "View connection tracking entries"),
            ("Search Rules", "search", "Search for rules"),
            ("Show Help", "help", "Show keyboard shortcuts and help"),
            ("Quit", "quit", "Exit the application"),
        ]

        query_lower = query.lower()

        for name, action, description in commands:
            if query_lower in name.lower() or query_lower in description.lower():
                yield Hit(
                    score=1.0 if query_lower in name.lower() else 0.5,
                    match_display=name,
                    command=lambda a=action: self._run_action(a),
                    help=description,
                )

    def _run_action(self, action: str) -> None:
        """Run the specified action."""
        screen = self.app.screen
        if hasattr(screen, f"action_{action}"):
            getattr(screen, f"action_{action}")()


class NFTApp(App):
    """Main nft-tui application."""

    TITLE = "NFT-TUI"
    SUB_TITLE = "nftables Terminal User Interface"
    CSS_PATH = "styles/app.tcss"
    COMMANDS = {NFTCommandProvider}

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
        ("?", "help", "Help"),
        ("ctrl+p", "command_palette", "Commands"),
    ]

    def __init__(self, sudo: bool = True) -> None:
        """Initialize the application.

        Args:
            sudo: Whether to use sudo for nft commands.
        """
        super().__init__()
        self._sudo = sudo
        self._client: NFTClient | None = None
        self._backup: BackupManager | None = None

    def on_mount(self) -> None:
        """Initialize on mount."""
        try:
            self._client = NFTClient(sudo=self._sudo)
            self._backup = BackupManager()

            # Check permissions
            has_perm, error = self._client.check_permissions()
            if not has_perm:
                self.notify(
                    f"Warning: {error}",
                    severity="warning",
                    timeout=5,
                )

            # Push the main screen
            self.push_screen(MainScreen(self._client, self._backup))

        except NFTError as e:
            self.notify(f"Failed to initialize: {e}", severity="error")
            self.exit(1)

    def action_quit(self) -> None:
        """Quit the application."""
        self.exit()

    def action_help(self) -> None:
        """Show help screen."""
        from .screens.help import HelpScreen

        self.push_screen(HelpScreen())


def run() -> None:
    """Run the nft-tui application."""
    import sys

    # Check for --no-sudo flag
    sudo = "--no-sudo" not in sys.argv

    app = NFTApp(sudo=sudo)
    app.run()
