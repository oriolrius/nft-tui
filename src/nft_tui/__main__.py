"""Entry point for nft-tui."""

from __future__ import annotations

import sys


def main() -> int:
    """Main entry point for nft-tui.

    Returns:
        Exit code.
    """
    # Handle help flag
    if "--help" in sys.argv or "-h" in sys.argv:
        print(
            """NFT-TUI - nftables Terminal User Interface

Usage: nft-tui [OPTIONS]

Options:
  --no-sudo    Run without sudo (requires root or CAP_NET_ADMIN)
  --help, -h   Show this help message
  --version    Show version information

Keyboard shortcuts:
  j/k          Navigate up/down
  Enter        Select/expand
  a            Add new item
  d            Delete selected
  e            Edit selected
  f            Flush chain/table
  r            Refresh
  i            Import ruleset
  x            Export ruleset
  u            Undo (restore backup)
  t            View connection tracking
  /            Search rules
  ?            Show help
  q            Quit
  Ctrl+P       Command palette

For more information, see: https://github.com/your-username/nft-tui
"""
        )
        return 0

    # Handle version flag
    if "--version" in sys.argv:
        from . import __version__

        print(f"nft-tui {__version__}")
        return 0

    # Run the app
    try:
        from .app import run

        run()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
