"""Rule editor widget."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.syntax import Syntax
from rich.text import Text
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Input, Static, TextArea

if TYPE_CHECKING:
    from ..nft.models import Rule


class RuleEditor(Vertical):
    """Widget for editing nftables rules."""

    class RuleSubmitted(Message):
        """Message sent when a rule is submitted."""

        def __init__(self, rule_spec: str) -> None:
            super().__init__()
            self.rule_spec = rule_spec

    class Cancelled(Message):
        """Message sent when editing is cancelled."""

        pass

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
        ("ctrl+s", "submit", "Submit"),
    ]

    def __init__(
        self,
        initial_value: str = "",
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the rule editor."""
        super().__init__(id=id, classes=classes)
        self._initial_value = initial_value
        self._text_area: TextArea | None = None
        self._validation_status: Static | None = None

    def compose(self):
        """Compose the rule editor layout."""
        yield Static("Enter rule specification:", classes="editor-label")
        yield Static(
            Text.from_markup(
                "[dim]Examples: [cyan]tcp dport 22 accept[/], "
                "[cyan]ip saddr 192.168.1.0/24 drop[/][/]"
            ),
            classes="editor-hint",
        )
        self._text_area = TextArea(
            self._initial_value,
            language="shell",
            theme="monokai",
            id="rule-input",
        )
        yield self._text_area
        self._validation_status = Static("", classes="validation-status")
        yield self._validation_status
        yield Static(
            Text.from_markup(
                "[dim]Press [bold]Ctrl+S[/] to submit, [bold]Escape[/] to cancel[/]"
            ),
            classes="editor-footer",
        )

    def on_mount(self) -> None:
        """Focus the text area when mounted."""
        if self._text_area:
            self._text_area.focus()

    def action_cancel(self) -> None:
        """Cancel editing."""
        self.post_message(self.Cancelled())

    def action_submit(self) -> None:
        """Submit the rule."""
        if self._text_area:
            rule_spec = self._text_area.text.strip()
            if rule_spec:
                self.post_message(self.RuleSubmitted(rule_spec))

    def set_validation_error(self, error: str) -> None:
        """Set a validation error message."""
        if self._validation_status:
            self._validation_status.update(
                Text(f"Error: {error}", style="red bold")
            )

    def set_validation_success(self) -> None:
        """Clear validation errors."""
        if self._validation_status:
            self._validation_status.update(
                Text("Rule syntax is valid", style="green")
            )

    def clear_validation(self) -> None:
        """Clear validation status."""
        if self._validation_status:
            self._validation_status.update("")

    @property
    def rule_spec(self) -> str:
        """Get the current rule specification."""
        if self._text_area:
            return self._text_area.text.strip()
        return ""


class RuleDetailView(Static):
    """Widget for displaying rule details."""

    def __init__(
        self,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the rule detail view."""
        super().__init__(id=id, classes=classes)
        self._rule: Rule | None = None

    def set_rule(self, rule: Rule | None) -> None:
        """Set the rule to display."""
        self._rule = rule
        self.refresh()

    def render(self) -> Text:
        """Render the rule details."""
        if not self._rule:
            return Text("Select a rule to view details", style="dim italic")

        rule = self._rule
        text = Text()

        # Header
        text.append("Rule Details\n", style="bold underline")
        text.append("\n")

        # Handle
        text.append("Handle: ", style="dim")
        text.append(str(rule.handle), style="cyan bold")
        text.append("\n")

        # Location
        text.append("Location: ", style="dim")
        text.append(f"{rule.family} {rule.table} {rule.chain}", style="white")
        text.append("\n")

        # Index
        if rule.index is not None:
            text.append("Position: ", style="dim")
            text.append(str(rule.index), style="white")
            text.append("\n")

        # Comment
        if rule.comment:
            text.append("Comment: ", style="dim")
            text.append(rule.comment, style="italic yellow")
            text.append("\n")

        text.append("\n")

        # Counter
        if rule.counter:
            text.append("Counters:\n", style="bold")
            text.append("  Packets: ", style="dim")
            text.append(rule.counter.format_packets(), style="green")
            text.append(f" ({rule.counter.packets:,})", style="dim")
            text.append("\n")
            text.append("  Bytes: ", style="dim")
            text.append(rule.counter.format_bytes(), style="green")
            text.append(f" ({rule.counter.bytes:,})", style="dim")
            text.append("\n\n")

        # Rule expression
        text.append("Expression:\n", style="bold")
        text.append("  ")
        text.append(rule.format_expr(), style="cyan")
        text.append("\n\n")

        # Raw expression breakdown
        text.append("Expression Breakdown:\n", style="bold dim")
        for i, expr in enumerate(rule.expr):
            text.append(f"  {i + 1}. ", style="dim")
            expr_type = next(iter(expr.keys()), "unknown")
            text.append(expr_type, style="yellow")
            if expr_type == "match":
                text.append(": ")
                match = expr["match"]
                left = str(match.get("left", ""))
                op = match.get("op", "==")
                right = str(match.get("right", ""))
                text.append(f"{left} {op} {right}", style="white")
            elif expr_type == "counter":
                pass  # Already shown above
            else:
                text.append(f": {expr.get(expr_type, '')}", style="white")
            text.append("\n")

        return text


class SyntaxHighlightInput(Input):
    """Input widget with nftables syntax hints."""

    KEYWORDS = {
        "accept",
        "drop",
        "reject",
        "return",
        "jump",
        "goto",
        "masquerade",
        "snat",
        "dnat",
        "redirect",
        "log",
        "counter",
        "limit",
        "queue",
        "notrack",
        "mark",
        "meta",
        "ct",
        "fib",
    }

    PROTOCOLS = {"tcp", "udp", "icmp", "icmpv6", "ip", "ip6", "arp", "ether"}

    META_KEYS = {
        "iifname",
        "oifname",
        "iif",
        "oif",
        "mark",
        "priority",
        "protocol",
        "length",
        "nfproto",
        "l4proto",
        "skuid",
        "skgid",
        "rtclassid",
    }

    def __init__(
        self,
        value: str = "",
        placeholder: str = "",
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize the syntax input."""
        super().__init__(
            value=value,
            placeholder=placeholder,
            id=id,
            classes=classes,
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle input changes for validation hints."""
        pass
