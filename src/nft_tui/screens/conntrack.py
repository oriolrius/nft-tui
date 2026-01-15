"""Connection tracking screen."""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, Input, Select, Static

from ..nft.conntrack import Connection, ConntrackClient, ConntrackError


class ConntrackScreen(Screen):
    """Screen for viewing connection tracking entries."""

    BINDINGS = [
        ("escape", "go_back", "Back"),
        ("q", "go_back", "Back"),
        ("r", "refresh", "Refresh"),
        ("f", "flush", "Flush"),
        ("d", "delete", "Delete"),
    ]

    def __init__(self, client: ConntrackClient | None = None) -> None:
        """Initialize the conntrack screen."""
        super().__init__()
        self._client = client
        self._connections: list[Connection] = []
        self._filter_protocol: str = ""
        self._filter_state: str = ""

    def compose(self) -> ComposeResult:
        """Compose the screen."""
        yield Header()

        with Vertical(classes="conntrack-container"):
            # Header info
            yield Static(
                "Connection Tracking",
                classes="screen-title",
            )

            # Filter controls
            with Horizontal(classes="filter-row"):
                yield Static("Protocol:", classes="filter-label")
                yield Select(
                    [
                        ("All", ""),
                        ("TCP", "tcp"),
                        ("UDP", "udp"),
                        ("ICMP", "icmp"),
                    ],
                    value="",
                    id="protocol-filter",
                )

                yield Static("State:", classes="filter-label")
                yield Select(
                    [
                        ("All", ""),
                        ("ESTABLISHED", "ESTABLISHED"),
                        ("SYN_SENT", "SYN_SENT"),
                        ("SYN_RECV", "SYN_RECV"),
                        ("FIN_WAIT", "FIN_WAIT"),
                        ("TIME_WAIT", "TIME_WAIT"),
                        ("CLOSE", "CLOSE"),
                        ("UNREPLIED", "UNREPLIED"),
                    ],
                    value="",
                    id="state-filter",
                )

                yield Button("Apply", variant="primary", id="apply-filter")
                yield Button("Refresh", variant="default", id="refresh-btn")

            # Connection count
            yield Static("", id="connection-count", classes="info-line")

            # Connections table
            yield DataTable(id="connections-table", cursor_type="row")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize the screen on mount."""
        # Set up the table
        table = self.query_one("#connections-table", DataTable)
        table.add_column("Proto", width=6, key="proto")
        table.add_column("State", width=12, key="state")
        table.add_column("Source", width=25, key="src")
        table.add_column("Destination", width=25, key="dst")
        table.add_column("Pkts→", width=10, key="pkts_orig")
        table.add_column("Bytes→", width=10, key="bytes_orig")
        table.add_column("Pkts←", width=10, key="pkts_reply")
        table.add_column("Bytes←", width=10, key="bytes_reply")
        table.add_column("Timeout", width=8, key="timeout")

        # Load connections
        self.refresh_connections()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "apply-filter":
            self.apply_filter()
        elif event.button.id == "refresh-btn":
            self.refresh_connections()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Handle filter selection changes."""
        if event.select.id == "protocol-filter":
            self._filter_protocol = str(event.value) if event.value else ""
        elif event.select.id == "state-filter":
            self._filter_state = str(event.value) if event.value else ""

    def apply_filter(self) -> None:
        """Apply the current filters."""
        self.refresh_connections()

    @work(exclusive=True)
    async def refresh_connections(self) -> None:
        """Refresh the connection list."""
        if not self._client:
            try:
                self._client = ConntrackClient()
            except ConntrackError as e:
                self.notify(str(e), severity="error")
                return

        try:
            self._connections = await self._client.list_connections_async(
                protocol=self._filter_protocol if self._filter_protocol else None,
                state=self._filter_state if self._filter_state else None,
            )
            self.update_table()
        except ConntrackError as e:
            self.notify(f"Failed to load connections: {e}", severity="error")

    def update_table(self) -> None:
        """Update the connections table."""
        table = self.query_one("#connections-table", DataTable)
        table.clear()

        for conn in self._connections:
            # Format values
            state_style = self._get_state_style(conn.state)

            table.add_row(
                conn.protocol.upper(),
                conn.state,
                conn.display_src,
                conn.display_dst,
                Connection.format_bytes(conn.packets_orig).replace("B", ""),
                Connection.format_bytes(conn.bytes_orig),
                Connection.format_bytes(conn.packets_reply).replace("B", ""),
                Connection.format_bytes(conn.bytes_reply),
                f"{conn.timeout}s" if conn.timeout else "-",
            )

        # Update count
        count_label = self.query_one("#connection-count", Static)
        count_label.update(f"Total connections: {len(self._connections)}")

    def _get_state_style(self, state: str) -> str:
        """Get style for connection state."""
        styles = {
            "ESTABLISHED": "green",
            "SYN_SENT": "yellow",
            "SYN_RECV": "yellow",
            "FIN_WAIT": "blue",
            "TIME_WAIT": "dim",
            "CLOSE": "dim",
            "UNREPLIED": "red",
        }
        return styles.get(state, "white")

    def action_go_back(self) -> None:
        """Go back to the main screen."""
        self.app.pop_screen()

    def action_refresh(self) -> None:
        """Refresh connections."""
        self.refresh_connections()

    @work
    async def action_flush(self) -> None:
        """Flush all connections."""
        if not self._client:
            return

        # Confirmation would be nice but keeping it simple
        try:
            protocol = self._filter_protocol if self._filter_protocol else None
            await self._client.flush_connections_async(protocol=protocol)
            self.notify("Connections flushed", severity="information")
            self.refresh_connections()
        except ConntrackError as e:
            self.notify(f"Failed to flush: {e}", severity="error")

    @work
    async def action_delete(self) -> None:
        """Delete the selected connection."""
        if not self._client:
            return

        table = self.query_one("#connections-table", DataTable)
        if table.cursor_row is None or table.cursor_row >= len(self._connections):
            return

        conn = self._connections[table.cursor_row]

        try:
            await self._client.delete_connection_async(
                protocol=conn.protocol,
                src=conn.src,
                dst=conn.dst,
                sport=conn.sport,
                dport=conn.dport,
            )
            self.notify("Connection deleted", severity="information")
            self.refresh_connections()
        except ConntrackError as e:
            self.notify(f"Failed to delete: {e}", severity="error")
