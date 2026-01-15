# NFT-TUI

Professional Terminal User Interface for managing nftables firewall rules.

![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **Tree Navigation** - Hierarchical view of tables, chains, and rules
- **Rule Management** - Add, edit, delete, and flush rules with validation
- **Live Counters** - Real-time packet and byte counter updates
- **Search & Filter** - Full-text search across all rules
- **Import/Export** - Load and save ruleset files
- **Backup System** - Automatic backups before destructive operations
- **Undo Support** - Restore from backup snapshots
- **Connection Tracking** - View active connections via conntrack
- **Vim Keybindings** - Familiar navigation with j/k, h/l
- **Command Palette** - Quick access to all commands with Ctrl+P
- **Dark Theme** - Modern, professional dark theme

## Installation

### Using uv (recommended)

```bash
uv tool install nft-tui
```

### Using pip

```bash
pip install nft-tui
```

### From source

```bash
git clone https://github.com/oriolrius/nft-tui.git
cd nft-tui
uv sync
uv run nft-tui
```

## Usage

```bash
# Run with sudo (default, required for nftables access)
nft-tui

# Run without sudo (requires root or CAP_NET_ADMIN)
nft-tui --no-sudo

# Show help
nft-tui --help
```

## Keyboard Shortcuts

### Navigation
| Key | Action |
|-----|--------|
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `h` / `←` | Collapse / Go back |
| `l` / `→` / `Enter` | Expand / Select |
| `g` | Go to top |
| `G` | Go to bottom |
| `Tab` | Switch panel focus |

### Actions
| Key | Action |
|-----|--------|
| `a` | Add new item |
| `e` | Edit selected |
| `d` | Delete selected |
| `f` | Flush chain/table |
| `r` | Refresh ruleset |
| `u` | Undo (restore backup) |

### Views
| Key | Action |
|-----|--------|
| `/` | Search rules |
| `t` | Connection tracking |
| `?` | Show help |
| `Ctrl+P` | Command palette |

### Import/Export
| Key | Action |
|-----|--------|
| `i` | Import ruleset |
| `x` | Export ruleset |

### General
| Key | Action |
|-----|--------|
| `q` | Quit |
| `Escape` | Cancel / Close dialog |

## Screenshots

```
┌─────────────────────────────────────────────────────────────────────┐
│  NFT-TUI                                            [?] Help  [q] Quit │
├─────────────────────┬───────────────────────────────────────────────┤
│ ▼ inet::filter     │  Chain: input (filter, hook: input, prio: 0)  │
│   ├─ input         │  Policy: accept                                │
│   ├─ forward       │─────────────────────────────────────────────────│
│   └─ output        │  #  │ Rule                          │ Pkts │ Bytes│
│ ▼ ip::nat          │─────┼───────────────────────────────┼──────┼──────│
│   ├─ prerouting    │  1  │ tcp dport 22 accept           │ 1.2K │ 98K  │
│   └─ postrouting   │  2  │ tcp dport 80 accept           │ 45K  │ 2.1M │
├─────────────────────┴───────────────────────────────────────────────┤
│ [a]dd  [e]dit  [d]elete  [f]lush  [/]search  [r]efresh  [i]mport    │
└─────────────────────────────────────────────────────────────────────┘
```

## Requirements

- Python 3.12+
- nftables installed (`nft` command available)
- sudo access or root privileges for firewall operations
- conntrack-tools (optional, for connection tracking)

## Development

```bash
# Clone the repository
git clone https://github.com/oriolrius/nft-tui.git
cd nft-tui

# Install with dev dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Run linter
uv run ruff check

# Run type checker
uv run mypy src/
```

## Architecture

```
src/nft_tui/
├── __init__.py          # Package info
├── __main__.py          # Entry point
├── app.py               # Main Textual App
├── nft/                 # nftables backend
│   ├── client.py        # NFT CLI interface
│   ├── conntrack.py     # Connection tracking
│   ├── models.py        # Data models
│   └── parser.py        # JSON parser
├── widgets/             # Custom widgets
│   ├── tree_view.py     # Ruleset tree
│   ├── table_view.py    # Rule table
│   ├── counters.py      # Counter display
│   └── dialogs.py       # Modal dialogs
├── screens/             # Application screens
│   ├── main.py          # Main screen
│   ├── conntrack.py     # Connection tracking
│   └── help.py          # Help overlay
├── styles/              # CSS styling
│   └── app.tcss         # Textual CSS
└── utils/               # Utilities
    ├── backup.py        # Backup management
    └── validators.py    # Input validation
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [Textual](https://textual.textualize.io/) - TUI framework
- [Rich](https://rich.readthedocs.io/) - Terminal formatting
- [nftables](https://netfilter.org/projects/nftables/) - Linux firewall
