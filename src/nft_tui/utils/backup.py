"""Backup management utilities."""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..nft.client import NFTClient


class BackupManager:
    """Manages ruleset backups."""

    def __init__(self, backup_dir: Path | None = None, max_backups: int = 50):
        """Initialize the backup manager.

        Args:
            backup_dir: Directory to store backups. Defaults to ~/.nft-tui/backups.
            max_backups: Maximum number of backups to keep.
        """
        self.backup_dir = backup_dir or (Path.home() / ".nft-tui" / "backups")
        self.max_backups = max_backups
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(self, client: NFTClient, name: str | None = None) -> Path:
        """Create a backup of the current ruleset.

        Args:
            client: NFT client to get the ruleset from.
            name: Optional name for the backup. Defaults to timestamp.

        Returns:
            Path to the created backup file.
        """
        if name is None:
            name = datetime.now().strftime("%Y%m%d_%H%M%S")

        backup_path = self.backup_dir / f"{name}.nft"
        content = client.export_ruleset()
        backup_path.write_text(content)

        self._cleanup_old_backups()
        return backup_path

    async def create_backup_async(self, client: NFTClient, name: str | None = None) -> Path:
        """Create a backup asynchronously."""
        if name is None:
            name = datetime.now().strftime("%Y%m%d_%H%M%S")

        backup_path = self.backup_dir / f"{name}.nft"
        content = await client.export_ruleset_async()
        backup_path.write_text(content)

        self._cleanup_old_backups()
        return backup_path

    def create_auto_backup(self, client: NFTClient) -> Path:
        """Create an auto-backup before destructive operations."""
        name = f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        return self.create_backup(client, name)

    async def create_auto_backup_async(self, client: NFTClient) -> Path:
        """Create an auto-backup asynchronously."""
        name = f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        return await self.create_backup_async(client, name)

    def list_backups(self) -> list[tuple[Path, datetime, int]]:
        """List all backups with their timestamps and sizes.

        Returns:
            List of (path, datetime, size_bytes) tuples, sorted by date descending.
        """
        backups = []
        for path in self.backup_dir.glob("*.nft"):
            try:
                # Try to parse timestamp from filename
                name = path.stem
                if name.startswith("auto_"):
                    name = name[5:]
                dt = datetime.strptime(name, "%Y%m%d_%H%M%S")
            except ValueError:
                dt = datetime.fromtimestamp(path.stat().st_mtime)

            size = path.stat().st_size
            backups.append((path, dt, size))

        return sorted(backups, key=lambda x: x[1], reverse=True)

    def get_backup(self, name: str) -> Path | None:
        """Get a backup by name."""
        path = self.backup_dir / f"{name}.nft"
        if path.exists():
            return path
        return None

    def get_latest_backup(self) -> Path | None:
        """Get the most recent backup."""
        backups = self.list_backups()
        if backups:
            return backups[0][0]
        return None

    def restore_backup(self, client: NFTClient, path: Path | str) -> None:
        """Restore a backup.

        Args:
            client: NFT client to restore with.
            path: Path to the backup file.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Backup not found: {path}")

        client.import_file(path)

    async def restore_backup_async(self, client: NFTClient, path: Path | str) -> None:
        """Restore a backup asynchronously."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Backup not found: {path}")

        await client.import_file_async(path)

    def delete_backup(self, path: Path | str) -> None:
        """Delete a backup."""
        path = Path(path)
        if path.exists():
            path.unlink()

    def _cleanup_old_backups(self) -> None:
        """Remove old backups if we exceed max_backups."""
        backups = self.list_backups()
        if len(backups) > self.max_backups:
            for path, _, _ in backups[self.max_backups :]:
                try:
                    path.unlink()
                except OSError:
                    pass

    def export_backup(self, path: Path | str, destination: Path | str) -> None:
        """Export a backup to a different location.

        Args:
            path: Path to the backup file.
            destination: Destination path.
        """
        path = Path(path)
        destination = Path(destination)
        if not path.exists():
            raise FileNotFoundError(f"Backup not found: {path}")

        shutil.copy2(path, destination)

    def get_backup_content(self, path: Path | str) -> str:
        """Get the content of a backup file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Backup not found: {path}")
        return path.read_text()

    def format_backup_size(self, size_bytes: int) -> str:
        """Format backup size for display."""
        if size_bytes >= 1_048_576:
            return f"{size_bytes / 1_048_576:.1f} MB"
        if size_bytes >= 1_024:
            return f"{size_bytes / 1_024:.1f} KB"
        return f"{size_bytes} B"
