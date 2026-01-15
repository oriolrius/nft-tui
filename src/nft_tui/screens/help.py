"""Help screen for nft-tui."""

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static, Markdown


HELP_TEXT = """
# NFT-TUI Help

## Navigation

| Key | Action |
|-----|--------|
| `j` / `↓` | Move cursor down |
| `k` / `↑` | Move cursor up |
| `h` / `←` | Collapse node / Go back |
| `l` / `→` / `Enter` | Expand node / Select |
| `g` | Go to top |
| `G` | Go to bottom |
| `Tab` | Switch focus between panels |

## Actions

| Key | Action |
|-----|--------|
| `a` | Add new item (table/chain/rule based on context) |
| `e` | Edit selected item |
| `d` | Delete selected item |
| `f` | Flush (clear all rules from chain/table) |
| `r` | Refresh the ruleset view |
| `u` | Undo (restore from last backup) |

## Search & Filter

| Key | Action |
|-----|--------|
| `/` | Open search dialog |
| `n` | Next search result |
| `N` | Previous search result |
| `Escape` | Clear search |

## Import/Export

| Key | Action |
|-----|--------|
| `i` | Import ruleset from file |
| `x` | Export ruleset to file |

## Views

| Key | Action |
|-----|--------|
| `c` | Toggle counter display |
| `t` | View connection tracking |
| `?` | Show this help |
| `Ctrl+P` | Open command palette |

## General

| Key | Action |
|-----|--------|
| `q` | Quit application |
| `Escape` | Close dialog / Cancel operation |

---

## About nftables

nftables is the modern Linux firewall framework that replaces iptables.
It provides a unified framework for packet filtering, NAT, and more.

### Structure

- **Tables**: Contain chains and sets, organized by address family
- **Chains**: Contain rules, can be base chains (with hooks) or regular
- **Rules**: Define the filtering logic with match expressions and actions
- **Sets**: Named collections of elements for efficient matching

### Address Families

- `ip` - IPv4 only
- `ip6` - IPv6 only
- `inet` - IPv4 and IPv6
- `arp` - ARP protocol
- `bridge` - Bridge filtering
- `netdev` - Network device (ingress/egress)

### Common Actions

- `accept` - Accept the packet
- `drop` - Silently drop the packet
- `reject` - Drop and send rejection
- `jump <chain>` - Jump to another chain
- `return` - Return from chain
- `masquerade` - Source NAT using outgoing interface address
- `snat` / `dnat` - Source/Destination NAT

---

Press `Escape` or `q` to close this help screen.
"""


class HelpScreen(ModalScreen):
    """Modal screen displaying help information."""

    BINDINGS = [
        ("escape", "close", "Close"),
        ("q", "close", "Close"),
        ("?", "close", "Close"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the help screen."""
        with VerticalScroll(classes="help-container"):
            yield Markdown(HELP_TEXT, classes="help-content")

    def action_close(self) -> None:
        """Close the help screen."""
        self.dismiss()
