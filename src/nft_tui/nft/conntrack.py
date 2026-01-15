"""Connection tracking (conntrack) interface."""

from __future__ import annotations

import asyncio
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


class ConntrackError(Exception):
    """Exception raised for conntrack command errors."""

    def __init__(self, message: str, command: str = "", returncode: int = 0):
        super().__init__(message)
        self.command = command
        self.returncode = returncode


@dataclass
class Connection:
    """A connection tracking entry."""

    protocol: str
    state: str
    src: str
    dst: str
    sport: int | None
    dport: int | None
    packets_orig: int
    bytes_orig: int
    packets_reply: int
    bytes_reply: int
    timeout: int | None = None
    mark: int | None = None
    zone: int | None = None
    assured: bool = False
    unreplied: bool = False

    @property
    def display_src(self) -> str:
        """Format source address:port."""
        if self.sport:
            return f"{self.src}:{self.sport}"
        return self.src

    @property
    def display_dst(self) -> str:
        """Format destination address:port."""
        if self.dport:
            return f"{self.dst}:{self.dport}"
        return self.dst

    @staticmethod
    def format_bytes(n: int) -> str:
        """Format bytes with human-readable suffix."""
        if n >= 1_073_741_824:
            return f"{n / 1_073_741_824:.1f}GB"
        if n >= 1_048_576:
            return f"{n / 1_048_576:.1f}MB"
        if n >= 1_024:
            return f"{n / 1_024:.1f}KB"
        return f"{n}B"


class ConntrackClient:
    """Client for interacting with connection tracking via conntrack CLI."""

    # Regex patterns for parsing conntrack output
    PROTO_PATTERN = re.compile(r"^(\w+)\s+(\d+)\s+(\d+)")
    SRC_PATTERN = re.compile(r"src=(\S+)")
    DST_PATTERN = re.compile(r"dst=(\S+)")
    SPORT_PATTERN = re.compile(r"sport=(\d+)")
    DPORT_PATTERN = re.compile(r"dport=(\d+)")
    PACKETS_PATTERN = re.compile(r"packets=(\d+)")
    BYTES_PATTERN = re.compile(r"bytes=(\d+)")
    MARK_PATTERN = re.compile(r"mark=(\d+)")
    ZONE_PATTERN = re.compile(r"zone=(\d+)")

    # State patterns for different protocols
    TCP_STATES = {
        "ESTABLISHED",
        "SYN_SENT",
        "SYN_RECV",
        "FIN_WAIT",
        "CLOSE_WAIT",
        "LAST_ACK",
        "TIME_WAIT",
        "CLOSE",
        "LISTEN",
    }

    def __init__(self, sudo: bool = True, conntrack_path: str | None = None):
        """Initialize the conntrack client.

        Args:
            sudo: Whether to use sudo for conntrack commands.
            conntrack_path: Path to conntrack binary. If None, will search PATH.
        """
        self.sudo = sudo
        self.conntrack_path = conntrack_path or self._find_conntrack()

    def _find_conntrack(self) -> str:
        """Find the conntrack binary."""
        conntrack = shutil.which("conntrack")
        if conntrack:
            return conntrack

        for path in ["/usr/sbin/conntrack", "/sbin/conntrack", "/usr/bin/conntrack"]:
            import os

            if os.path.exists(path):
                return path

        raise ConntrackError("conntrack binary not found. Is conntrack-tools installed?")

    def _build_command(self, args: Sequence[str]) -> list[str]:
        """Build the full command with optional sudo."""
        cmd = []
        if self.sudo:
            cmd.append("sudo")
        cmd.append(self.conntrack_path)
        cmd.extend(args)
        return cmd

    def _run(self, args: Sequence[str], check: bool = True) -> str:
        """Execute a conntrack command synchronously."""
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
            raise ConntrackError(f"Command timed out: {cmd_str}", cmd_str) from e
        except Exception as e:
            raise ConntrackError(f"Failed to execute command: {e}", cmd_str) from e

        if check and result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            if "Permission denied" in error_msg or "Operation not permitted" in error_msg:
                raise ConntrackError(
                    "Permission denied. Try running with sudo.",
                    cmd_str,
                    result.returncode,
                )
            raise ConntrackError(
                f"conntrack command failed: {error_msg}",
                cmd_str,
                result.returncode,
            )

        return result.stdout

    async def _run_async(self, args: Sequence[str], check: bool = True) -> str:
        """Execute a conntrack command asynchronously."""
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
            raise ConntrackError(f"Command timed out: {cmd_str}", cmd_str) from e
        except Exception as e:
            raise ConntrackError(f"Failed to execute command: {e}", cmd_str) from e

        stdout_str = stdout.decode()
        stderr_str = stderr.decode()

        if check and process.returncode != 0:
            error_msg = stderr_str.strip() or stdout_str.strip()
            raise ConntrackError(
                f"conntrack command failed: {error_msg}",
                cmd_str,
                process.returncode or 1,
            )

        return stdout_str

    def _parse_line(self, line: str) -> Connection | None:
        """Parse a single conntrack line into a Connection object."""
        line = line.strip()
        if not line:
            return None

        # Extract protocol and timeout
        proto_match = self.PROTO_PATTERN.match(line)
        if not proto_match:
            return None

        protocol = proto_match.group(1).lower()
        timeout = int(proto_match.group(3))

        # Determine state based on protocol
        state = "UNKNOWN"
        for tcp_state in self.TCP_STATES:
            if tcp_state in line:
                state = tcp_state
                break

        if "ASSURED" in line:
            assured = True
        else:
            assured = False

        if "UNREPLIED" in line:
            unreplied = True
            state = "UNREPLIED"
        else:
            unreplied = False

        # Extract source and destination (first occurrence is original direction)
        src_matches = self.SRC_PATTERN.findall(line)
        dst_matches = self.DST_PATTERN.findall(line)
        sport_matches = self.SPORT_PATTERN.findall(line)
        dport_matches = self.DPORT_PATTERN.findall(line)
        packets_matches = self.PACKETS_PATTERN.findall(line)
        bytes_matches = self.BYTES_PATTERN.findall(line)

        src = src_matches[0] if src_matches else ""
        dst = dst_matches[0] if dst_matches else ""
        sport = int(sport_matches[0]) if sport_matches else None
        dport = int(dport_matches[0]) if dport_matches else None

        # Packets and bytes: first pair is original, second is reply
        packets_orig = int(packets_matches[0]) if len(packets_matches) > 0 else 0
        bytes_orig = int(bytes_matches[0]) if len(bytes_matches) > 0 else 0
        packets_reply = int(packets_matches[1]) if len(packets_matches) > 1 else 0
        bytes_reply = int(bytes_matches[1]) if len(bytes_matches) > 1 else 0

        # Extract mark and zone
        mark_match = self.MARK_PATTERN.search(line)
        zone_match = self.ZONE_PATTERN.search(line)
        mark = int(mark_match.group(1)) if mark_match else None
        zone = int(zone_match.group(1)) if zone_match else None

        return Connection(
            protocol=protocol,
            state=state,
            src=src,
            dst=dst,
            sport=sport,
            dport=dport,
            packets_orig=packets_orig,
            bytes_orig=bytes_orig,
            packets_reply=packets_reply,
            bytes_reply=bytes_reply,
            timeout=timeout,
            mark=mark,
            zone=zone,
            assured=assured,
            unreplied=unreplied,
        )

    def list_connections(
        self,
        protocol: str | None = None,
        src: str | None = None,
        dst: str | None = None,
        state: str | None = None,
    ) -> list[Connection]:
        """List connection tracking entries.

        Args:
            protocol: Filter by protocol (tcp, udp, icmp, etc.).
            src: Filter by source address.
            dst: Filter by destination address.
            state: Filter by connection state.

        Returns:
            List of Connection objects.
        """
        args = ["-L"]

        if protocol:
            args.extend(["-p", protocol])
        if src:
            args.extend(["-s", src])
        if dst:
            args.extend(["-d", dst])

        try:
            output = self._run(args)
        except ConntrackError:
            return []

        connections = []
        for line in output.splitlines():
            conn = self._parse_line(line)
            if conn:
                if state and conn.state != state:
                    continue
                connections.append(conn)

        return connections

    async def list_connections_async(
        self,
        protocol: str | None = None,
        src: str | None = None,
        dst: str | None = None,
        state: str | None = None,
    ) -> list[Connection]:
        """List connection tracking entries asynchronously."""
        args = ["-L"]

        if protocol:
            args.extend(["-p", protocol])
        if src:
            args.extend(["-s", src])
        if dst:
            args.extend(["-d", dst])

        try:
            output = await self._run_async(args)
        except ConntrackError:
            return []

        connections = []
        for line in output.splitlines():
            conn = self._parse_line(line)
            if conn:
                if state and conn.state != state:
                    continue
                connections.append(conn)

        return connections

    def count_connections(self) -> int:
        """Get the count of tracked connections."""
        try:
            output = self._run(["-C"])
            return int(output.strip())
        except (ConntrackError, ValueError):
            return 0

    async def count_connections_async(self) -> int:
        """Get the count of tracked connections asynchronously."""
        try:
            output = await self._run_async(["-C"])
            return int(output.strip())
        except (ConntrackError, ValueError):
            return 0

    def flush_connections(self, protocol: str | None = None) -> None:
        """Flush connection tracking entries.

        Args:
            protocol: If specified, only flush connections of this protocol.
        """
        args = ["-F"]
        if protocol:
            args.extend(["-p", protocol])
        self._run(args)

    async def flush_connections_async(self, protocol: str | None = None) -> None:
        """Flush connection tracking entries asynchronously."""
        args = ["-F"]
        if protocol:
            args.extend(["-p", protocol])
        await self._run_async(args)

    def delete_connection(
        self,
        protocol: str,
        src: str,
        dst: str,
        sport: int | None = None,
        dport: int | None = None,
    ) -> None:
        """Delete a specific connection.

        Args:
            protocol: Connection protocol.
            src: Source address.
            dst: Destination address.
            sport: Source port (for TCP/UDP).
            dport: Destination port (for TCP/UDP).
        """
        args = ["-D", "-p", protocol, "-s", src, "-d", dst]
        if sport:
            args.extend(["--sport", str(sport)])
        if dport:
            args.extend(["--dport", str(dport)])
        self._run(args, check=False)

    async def delete_connection_async(
        self,
        protocol: str,
        src: str,
        dst: str,
        sport: int | None = None,
        dport: int | None = None,
    ) -> None:
        """Delete a specific connection asynchronously."""
        args = ["-D", "-p", protocol, "-s", src, "-d", dst]
        if sport:
            args.extend(["--sport", str(sport)])
        if dport:
            args.extend(["--dport", str(dport)])
        await self._run_async(args, check=False)

    def get_statistics(self) -> dict[str, int]:
        """Get connection tracking statistics.

        Returns:
            Dictionary with statistics.
        """
        try:
            output = self._run(["-S"])
        except ConntrackError:
            return {}

        stats: dict[str, int] = {}
        for line in output.splitlines():
            line = line.strip()
            if "=" in line:
                parts = line.split()
                for part in parts:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        try:
                            stats[key] = int(value)
                        except ValueError:
                            pass

        return stats

    async def get_statistics_async(self) -> dict[str, int]:
        """Get connection tracking statistics asynchronously."""
        try:
            output = await self._run_async(["-S"])
        except ConntrackError:
            return {}

        stats: dict[str, int] = {}
        for line in output.splitlines():
            line = line.strip()
            if "=" in line:
                parts = line.split()
                for part in parts:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        try:
                            stats[key] = int(value)
                        except ValueError:
                            pass

        return stats

    def is_available(self) -> bool:
        """Check if conntrack is available and we have permissions."""
        try:
            self._run(["-C"])
            return True
        except ConntrackError:
            return False
