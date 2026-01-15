# NFT-TUI: Professional nftables Terminal User Interface

## Project Overview
A professional-grade Terminal User Interface for managing nftables firewall rules using Python, `uv` package manager, and the `textual` TUI framework.

## Architecture

### Project Structure
```
nft-tui/
├── pyproject.toml           # Project config with uv
├── README.md                 # Documentation
├── src/
│   └── nft_tui/
│       ├── __init__.py
│       ├── __main__.py       # Entry point
│       ├── app.py            # Main Textual App
│       ├── nft/              # nftables backend
│       │   ├── __init__.py
│       │   ├── client.py     # NFT CLI interface
│       │   ├── conntrack.py  # Connection tracking interface
│       │   ├── models.py     # Data models (Table, Chain, Rule, Set)
│       │   └── parser.py     # JSON parser for nft output
│       ├── widgets/          # Custom Textual widgets
│       │   ├── __init__.py
│       │   ├── tree_view.py  # Ruleset tree navigation
│       │   ├── rule_editor.py # Rule editing widget
│       │   ├── table_view.py # Table/details display
│       │   ├── counters.py   # Live counter display
│       │   └── dialogs.py    # Modal dialogs (add/edit/delete)
│       ├── screens/          # Application screens
│       │   ├── __init__.py
│       │   ├── main.py       # Main dashboard screen
│       │   ├── editor.py     # Full-screen editor
│       │   ├── conntrack.py  # Connection tracking screen
│       │   └── help.py       # Help overlay screen
│       ├── styles/           # CSS styling
│       │   └── app.tcss      # Textual CSS
│       └── utils/
│           ├── __init__.py
│           ├── backup.py     # Ruleset backup/restore
│           └── validators.py # Input validation
└── tests/                    # Test suite
    ├── __init__.py
    ├── test_client.py
    ├── test_models.py
    └── test_parser.py
```

### Core Components

#### 1. NFT Client (`src/nft_tui/nft/client.py`)
- Execute nft commands via subprocess with sudo
- JSON output parsing (-j flag)
- Operations: list, add, delete, flush, insert rules
- Error handling and validation (-c --check flag)
- Atomic operations support

#### 2. Data Models (`src/nft_tui/nft/models.py`)
```python
@dataclass
class Table:
    family: str  # ip, ip6, inet, arp, bridge, netdev
    name: str
    handle: int
    chains: list[Chain]
    sets: list[Set]

@dataclass
class Chain:
    name: str
    handle: int
    type: str | None  # filter, nat, route
    hook: str | None  # input, output, forward, prerouting, postrouting
    priority: int | None
    policy: str | None  # accept, drop
    rules: list[Rule]

@dataclass
class Rule:
    handle: int
    expr: list[dict]  # Expression tree
    comment: str | None
    counter: Counter | None
```

#### 3. Main Application (`src/nft_tui/app.py`)
- Textual App subclass
- Screen management
- Keybindings (vim-style + standard)
- Command palette integration
- Theme support (dark/light)

### UI Layout

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
│ ▼ ip::raw          │  3  │ icmp type echo-request accept │ 234  │ 12K  │
│   └─ PREROUTING    │  4  │ ct state established accept   │ 89K  │ 45M  │
│ ► Sets             │  5  │ counter drop                  │ 1.1K │ 67K  │
├─────────────────────┴───────────────────────────────────────────────┤
│ [a]dd  [e]dit  [d]elete  [f]lush  [/]search  [r]efresh  [i]mport    │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Features

1. **Tree Navigation** - Hierarchical view of tables → chains → rules
2. **Rule Details** - Expanded view with counters, expressions, comments
3. **CRUD Operations** - Add/Edit/Delete tables, chains, rules, sets
4. **Live Counters** - Real-time packet/byte counter updates
5. **Search & Filter** - Full-text search across rules
6. **Import/Export** - Load/save ruleset files
7. **Backup System** - Auto-backup before destructive operations
8. **Validation** - Check rules with `nft -c` before applying
9. **Syntax Highlighting** - Color-coded rule expressions
10. **Vim Keybindings** - j/k navigation, /search, etc.
11. **Command Palette** - Ctrl+P for quick actions
12. **Undo Support** - Restore from backup snapshots

### Keybindings
| Key | Action |
|-----|--------|
| j/↓ | Move down |
| k/↑ | Move up |
| Enter/l | Expand/select |
| h | Collapse/back |
| a | Add new item |
| e | Edit selected |
| d | Delete selected |
| f | Flush chain/table |
| / | Search |
| r | Refresh ruleset |
| c | View counters |
| i | Import ruleset |
| x | Export ruleset |
| u | Undo last change |
| ? | Show help |
| q | Quit |
| Ctrl+P | Command palette |

## Implementation Steps

### Phase 1: Project Setup
1. Initialize uv project with pyproject.toml
2. Create directory structure
3. Add dependencies: textual, rich

### Phase 2: NFT Backend
4. Implement NFT client with subprocess calls
5. Create data models for Table, Chain, Rule, Set
6. Build JSON parser for nft output
7. Add validation and error handling

### Phase 3: Core UI
8. Create main Textual App with styling
9. Build tree navigation widget
10. Implement rule table/details view
11. Create footer with keybindings

### Phase 4: CRUD Operations
12. Add table creation dialog
13. Add chain creation dialog
14. Add rule creation/editing dialog
15. Implement delete confirmations
16. Add flush operations

### Phase 5: Advanced Features
17. Live counter refresh
18. Search/filter functionality
19. Import/export dialogs
20. Backup/restore system
21. Undo functionality
22. Connection tracking viewer (conntrack -L parsing)

### Phase 6: Polish
23. Add help screen
24. Command palette integration
25. Error notifications (toasts)
26. Theme customization
27. Comprehensive CSS styling

## Dependencies
```toml
[project]
dependencies = [
    "textual>=3.0.0",
    "rich>=13.0.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0.0",
    "pytest-asyncio>=0.24.0",
]
```

## Verification Plan
1. Run `uv run nft-tui` and verify app launches
2. Test navigation through tables/chains/rules
3. Test add/edit/delete operations (with validation)
4. Verify counter refresh works
5. Test import/export functionality
6. Verify backup is created before destructive ops
7. Test search/filter
8. Run test suite with `uv run pytest`

## Configuration (Based on User Preferences)
- **Sudo Access**: Prompt for sudo when needed (standard approach)
- **Default Theme**: Dark theme optimized for terminals
- **Extra Feature**: Connection tracking viewer (conntrack integration)

## Notes
- Requires sudo/root for nft operations - will prompt via sudo
- Uses `-j` JSON flag for structured output
- Uses `-c` check flag for validation before applying
- Auto-backup to ~/.nft-tui/backups/ before changes
- Conntrack integration for viewing active connections
