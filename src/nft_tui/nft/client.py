"""nftables CLI client interface."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from .models import Chain, Rule, RuleSet, Set, Table
from .parser import NFTParser

if TYPE_CHECKING:
    from collections.abc import Sequence


class NFTError(Exception):
    """Exception raised for nft command errors."""

    def __init__(self, message: str, command: str = "", returncode: int = 0):
        super().__init__(message)
        self.command = command
        self.returncode = returncode


class NFTClient:
    """Client for interacting with nftables via nft CLI."""

    def __init__(self, sudo: bool = True, nft_path: str | None = None):
        """Initialize the NFT client.

        Args:
            sudo: Whether to use sudo for nft commands.
            nft_path: Path to nft binary. If None, will search PATH.
        """
        self.sudo = sudo
        self.nft_path = nft_path or self._find_nft()
        self.parser = NFTParser()
        self._backup_dir = Path.home() / ".nft-tui" / "backups"

    def _find_nft(self) -> str:
        """Find the nft binary."""
        nft = shutil.which("nft")
        if nft:
            return nft

        for path in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]:
            if os.path.exists(path):
                return path

        raise NFTError("nft binary not found. Is nftables installed?")

    def _build_command(self, args: Sequence[str]) -> list[str]:
        """Build the full command with optional sudo."""
        cmd = []
        if self.sudo:
            cmd.append("sudo")
        cmd.append(self.nft_path)
        cmd.extend(args)
        return cmd

    def _run(self, args: Sequence[str], check: bool = True) -> str:
        """Execute an nft command synchronously.

        Args:
            args: Arguments to pass to nft.
            check: Whether to raise on non-zero exit.

        Returns:
            Command stdout.

        Raises:
            NFTError: If command fails and check is True.
        """
        cmd = self._build_command(args)
        cmd_str = " ".join(cmd)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.TimeoutExpired as e:
            raise NFTError(f"Command timed out: {cmd_str}", cmd_str) from e
        except Exception as e:
            raise NFTError(f"Failed to execute command: {e}", cmd_str) from e

        if check and result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            raise NFTError(
                f"nft command failed: {error_msg}",
                cmd_str,
                result.returncode,
            )

        return result.stdout

    async def _run_async(self, args: Sequence[str], check: bool = True) -> str:
        """Execute an nft command asynchronously.

        Args:
            args: Arguments to pass to nft.
            check: Whether to raise on non-zero exit.

        Returns:
            Command stdout.

        Raises:
            NFTError: If command fails and check is True.
        """
        cmd = self._build_command(args)
        cmd_str = " ".join(cmd)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=30,
            )
        except asyncio.TimeoutError as e:
            raise NFTError(f"Command timed out: {cmd_str}", cmd_str) from e
        except Exception as e:
            raise NFTError(f"Failed to execute command: {e}", cmd_str) from e

        stdout_str = stdout.decode()
        stderr_str = stderr.decode()

        if check and process.returncode != 0:
            error_msg = stderr_str.strip() or stdout_str.strip()
            raise NFTError(
                f"nft command failed: {error_msg}",
                cmd_str,
                process.returncode or 1,
            )

        return stdout_str

    def list_ruleset(self) -> RuleSet:
        """Get the complete ruleset."""
        output = self._run(["-j", "-a", "list", "ruleset"])
        return self.parser.parse_ruleset(output)

    async def list_ruleset_async(self) -> RuleSet:
        """Get the complete ruleset asynchronously."""
        output = await self._run_async(["-j", "-a", "list", "ruleset"])
        return self.parser.parse_ruleset(output)

    def list_tables(self) -> list[Table]:
        """List all tables."""
        output = self._run(["-j", "list", "tables"])
        return self.parser.parse_tables(output)

    async def list_tables_async(self) -> list[Table]:
        """List all tables asynchronously."""
        output = await self._run_async(["-j", "list", "tables"])
        return self.parser.parse_tables(output)

    def get_table(self, family: str, name: str) -> Table:
        """Get a specific table with its chains and rules."""
        output = self._run(["-j", "list", "table", family, name])
        ruleset = self.parser.parse_ruleset(output)
        table = ruleset.get_table(family, name)
        if not table:
            raise NFTError(f"Table {family} {name} not found")
        return table

    async def get_table_async(self, family: str, name: str) -> Table:
        """Get a specific table asynchronously."""
        output = await self._run_async(["-j", "list", "table", family, name])
        ruleset = self.parser.parse_ruleset(output)
        table = ruleset.get_table(family, name)
        if not table:
            raise NFTError(f"Table {family} {name} not found")
        return table

    def get_chain(self, family: str, table: str, chain: str) -> Chain:
        """Get a specific chain with its rules."""
        output = self._run(["-j", "-a", "list", "chain", family, table, chain])
        ruleset = self.parser.parse_ruleset(output)
        chain_obj = ruleset.get_chain(family, table, chain)
        if not chain_obj:
            raise NFTError(f"Chain {family} {table} {chain} not found")
        return chain_obj

    async def get_chain_async(self, family: str, table: str, chain: str) -> Chain:
        """Get a specific chain asynchronously."""
        output = await self._run_async(["-j", "-a", "list", "chain", family, table, chain])
        ruleset = self.parser.parse_ruleset(output)
        chain_obj = ruleset.get_chain(family, table, chain)
        if not chain_obj:
            raise NFTError(f"Chain {family} {table} {chain} not found")
        return chain_obj

    def validate(self, command: str) -> tuple[bool, str]:
        """Validate an nft command without applying it.

        Args:
            command: The nft command to validate.

        Returns:
            Tuple of (is_valid, error_message).
        """
        try:
            self._run(["-c"] + command.split())
            return True, ""
        except NFTError as e:
            return False, str(e)

    async def validate_async(self, command: str) -> tuple[bool, str]:
        """Validate an nft command asynchronously."""
        try:
            await self._run_async(["-c"] + command.split())
            return True, ""
        except NFTError as e:
            return False, str(e)

    def add_table(self, family: str, name: str) -> None:
        """Create a new table."""
        self._run(["add", "table", family, name])

    async def add_table_async(self, family: str, name: str) -> None:
        """Create a new table asynchronously."""
        await self._run_async(["add", "table", family, name])

    def delete_table(self, family: str, name: str) -> None:
        """Delete a table."""
        self._run(["delete", "table", family, name])

    async def delete_table_async(self, family: str, name: str) -> None:
        """Delete a table asynchronously."""
        await self._run_async(["delete", "table", family, name])

    def flush_table(self, family: str, name: str) -> None:
        """Flush all rules from a table."""
        self._run(["flush", "table", family, name])

    async def flush_table_async(self, family: str, name: str) -> None:
        """Flush all rules from a table asynchronously."""
        await self._run_async(["flush", "table", family, name])

    def add_chain(
        self,
        family: str,
        table: str,
        name: str,
        chain_type: str | None = None,
        hook: str | None = None,
        priority: int | None = None,
        policy: str | None = None,
        device: str | None = None,
    ) -> None:
        """Create a new chain."""
        if chain_type and hook and priority is not None:
            spec = f"{{ type {chain_type} hook {hook} priority {priority}"
            if device:
                spec += f" device {device}"
            if policy:
                spec += f"; policy {policy}"
            spec += "; }"
            self._run(["add", "chain", family, table, name, spec])
        else:
            self._run(["add", "chain", family, table, name])

    async def add_chain_async(
        self,
        family: str,
        table: str,
        name: str,
        chain_type: str | None = None,
        hook: str | None = None,
        priority: int | None = None,
        policy: str | None = None,
        device: str | None = None,
    ) -> None:
        """Create a new chain asynchronously."""
        if chain_type and hook and priority is not None:
            spec = f"{{ type {chain_type} hook {hook} priority {priority}"
            if device:
                spec += f" device {device}"
            if policy:
                spec += f"; policy {policy}"
            spec += "; }"
            await self._run_async(["add", "chain", family, table, name, spec])
        else:
            await self._run_async(["add", "chain", family, table, name])

    def delete_chain(self, family: str, table: str, name: str) -> None:
        """Delete a chain."""
        self._run(["delete", "chain", family, table, name])

    async def delete_chain_async(self, family: str, table: str, name: str) -> None:
        """Delete a chain asynchronously."""
        await self._run_async(["delete", "chain", family, table, name])

    def flush_chain(self, family: str, table: str, name: str) -> None:
        """Flush all rules from a chain."""
        self._run(["flush", "chain", family, table, name])

    async def flush_chain_async(self, family: str, table: str, name: str) -> None:
        """Flush all rules from a chain asynchronously."""
        await self._run_async(["flush", "chain", family, table, name])

    def set_chain_policy(self, family: str, table: str, name: str, policy: str) -> None:
        """Set chain policy (accept/drop)."""
        cmd = f"chain {family} {table} {name} {{ policy {policy}; }}"
        self._run(["add", cmd])

    def add_rule(
        self,
        family: str,
        table: str,
        chain: str,
        rule_spec: str,
        position: int | None = None,
        index: int | None = None,
    ) -> None:
        """Add a rule to a chain.

        Args:
            family: Address family.
            table: Table name.
            chain: Chain name.
            rule_spec: Rule specification (e.g., "tcp dport 22 accept").
            position: Insert after rule with this handle.
            index: Insert at this index position.
        """
        args = ["add", "rule", family, table, chain]
        if position is not None:
            args = ["insert", "rule", family, table, chain, "position", str(position)]
        elif index is not None:
            args = ["insert", "rule", family, table, chain, "index", str(index)]

        args.extend(rule_spec.split())
        self._run(args)

    async def add_rule_async(
        self,
        family: str,
        table: str,
        chain: str,
        rule_spec: str,
        position: int | None = None,
        index: int | None = None,
    ) -> None:
        """Add a rule asynchronously."""
        args = ["add", "rule", family, table, chain]
        if position is not None:
            args = ["insert", "rule", family, table, chain, "position", str(position)]
        elif index is not None:
            args = ["insert", "rule", family, table, chain, "index", str(index)]

        args.extend(rule_spec.split())
        await self._run_async(args)

    def delete_rule(self, family: str, table: str, chain: str, handle: int) -> None:
        """Delete a rule by handle."""
        self._run(["delete", "rule", family, table, chain, "handle", str(handle)])

    async def delete_rule_async(self, family: str, table: str, chain: str, handle: int) -> None:
        """Delete a rule asynchronously."""
        await self._run_async(["delete", "rule", family, table, chain, "handle", str(handle)])

    def replace_rule(
        self,
        family: str,
        table: str,
        chain: str,
        handle: int,
        rule_spec: str,
    ) -> None:
        """Replace a rule by handle."""
        args = ["replace", "rule", family, table, chain, "handle", str(handle)]
        args.extend(rule_spec.split())
        self._run(args)

    async def replace_rule_async(
        self,
        family: str,
        table: str,
        chain: str,
        handle: int,
        rule_spec: str,
    ) -> None:
        """Replace a rule asynchronously."""
        args = ["replace", "rule", family, table, chain, "handle", str(handle)]
        args.extend(rule_spec.split())
        await self._run_async(args)

    def add_set(
        self,
        family: str,
        table: str,
        name: str,
        set_type: str,
        flags: list[str] | None = None,
        timeout: int | None = None,
        comment: str | None = None,
    ) -> None:
        """Create a new set."""
        spec = f"{{ type {set_type}"
        if flags:
            spec += f"; flags {', '.join(flags)}"
        if timeout:
            spec += f"; timeout {timeout}s"
        if comment:
            spec += f'; comment "{comment}"'
        spec += "; }"
        self._run(["add", "set", family, table, name, spec])

    def delete_set(self, family: str, table: str, name: str) -> None:
        """Delete a set."""
        self._run(["delete", "set", family, table, name])

    def add_set_element(self, family: str, table: str, set_name: str, element: str) -> None:
        """Add an element to a set."""
        self._run(["add", "element", family, table, set_name, "{", element, "}"])

    def delete_set_element(self, family: str, table: str, set_name: str, element: str) -> None:
        """Delete an element from a set."""
        self._run(["delete", "element", family, table, set_name, "{", element, "}"])

    def flush_set(self, family: str, table: str, name: str) -> None:
        """Flush all elements from a set."""
        self._run(["flush", "set", family, table, name])

    def flush_ruleset(self) -> None:
        """Flush the entire ruleset."""
        self._run(["flush", "ruleset"])

    async def flush_ruleset_async(self) -> None:
        """Flush the entire ruleset asynchronously."""
        await self._run_async(["flush", "ruleset"])

    def export_ruleset(self) -> str:
        """Export the ruleset in nft format."""
        return self._run(["list", "ruleset"])

    async def export_ruleset_async(self) -> str:
        """Export the ruleset asynchronously."""
        return await self._run_async(["list", "ruleset"])

    def import_ruleset(self, content: str) -> None:
        """Import a ruleset from nft format content."""
        cmd = self._build_command(["-f", "-"])
        try:
            result = subprocess.run(
                cmd,
                input=content,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                raise NFTError(
                    f"Failed to import ruleset: {result.stderr}",
                    "nft -f -",
                    result.returncode,
                )
        except subprocess.TimeoutExpired as e:
            raise NFTError("Import timed out", "nft -f -") from e

    def import_file(self, path: str | Path) -> None:
        """Import a ruleset from a file."""
        path = Path(path)
        if not path.exists():
            raise NFTError(f"File not found: {path}")
        self._run(["-f", str(path)])

    async def import_file_async(self, path: str | Path) -> None:
        """Import a ruleset from a file asynchronously."""
        path = Path(path)
        if not path.exists():
            raise NFTError(f"File not found: {path}")
        await self._run_async(["-f", str(path)])

    def create_backup(self, name: str | None = None) -> Path:
        """Create a backup of the current ruleset.

        Args:
            name: Optional backup name. If None, uses timestamp.

        Returns:
            Path to the backup file.
        """
        from datetime import datetime

        self._backup_dir.mkdir(parents=True, exist_ok=True)

        if name is None:
            name = datetime.now().strftime("%Y%m%d_%H%M%S")

        backup_path = self._backup_dir / f"{name}.nft"
        content = self.export_ruleset()
        backup_path.write_text(content)

        return backup_path

    async def create_backup_async(self, name: str | None = None) -> Path:
        """Create a backup asynchronously."""
        from datetime import datetime

        self._backup_dir.mkdir(parents=True, exist_ok=True)

        if name is None:
            name = datetime.now().strftime("%Y%m%d_%H%M%S")

        backup_path = self._backup_dir / f"{name}.nft"
        content = await self.export_ruleset_async()
        backup_path.write_text(content)

        return backup_path

    def list_backups(self) -> list[Path]:
        """List all backup files."""
        if not self._backup_dir.exists():
            return []
        return sorted(self._backup_dir.glob("*.nft"), reverse=True)

    def restore_backup(self, path: str | Path) -> None:
        """Restore a backup file."""
        self.import_file(path)

    async def restore_backup_async(self, path: str | Path) -> None:
        """Restore a backup file asynchronously."""
        await self.import_file_async(path)

    def reset_counters(self, family: str | None = None, table: str | None = None) -> None:
        """Reset counters.

        If family and table are provided, resets counters for that table.
        Otherwise resets all counters.
        """
        if family and table:
            self._run(["reset", "counters", "table", family, table])
        else:
            self._run(["reset", "counters"])

    async def reset_counters_async(
        self, family: str | None = None, table: str | None = None
    ) -> None:
        """Reset counters asynchronously."""
        if family and table:
            await self._run_async(["reset", "counters", "table", family, table])
        else:
            await self._run_async(["reset", "counters"])

    def check_permissions(self) -> tuple[bool, str]:
        """Check if we have permission to execute nft commands.

        Returns:
            Tuple of (has_permission, error_message).
        """
        try:
            self._run(["-v"])
            self._run(["list", "tables"])
            return True, ""
        except NFTError as e:
            if "permission denied" in str(e).lower():
                return False, "Permission denied. Try running with sudo."
            return False, str(e)
