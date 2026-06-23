"""
Memory Persistence Manager

Manages persistent storage of AI context using JSONL format.
Writes context asynchronously to avoid blocking scanning operations.
"""
import json
import asyncio
from pathlib import Path
from datetime import datetime
from typing import Any, Optional, List
from threading import Lock
import aiofiles


class MemoryPersistence:
    """Manages persistent memory storage using JSONL format"""

    def __init__(self, context_file: str = "matthunder_context.md"):
        """
        Initialize memory persistence manager

        Args:
            context_file: Path to context storage file
        """
        self.context_file = Path(context_file)
        self.lock = Lock()
        self._ensure_file_exists()

    def _ensure_file_exists(self) -> None:
        """Ensure context file exists"""
        if not self.context_file.exists():
            self.context_file.write_text("# Matthunder AI Context\n", encoding='utf-8')

    def _get_context_header(self) -> str:
        """Get context file header"""
        return """# Matthunder AI Context

This file contains persistent context for AI reasoning across scanning sessions.
Format: JSONL (JSON Lines) - one JSON object per line

## Structure

```json
{
  "timestamp": "2026-06-22T10:00:00Z",
  "target_metadata": {...},
  "reconnaissance_map": {...},
  "vulnerability_journal": {...}
}
```

## Context Types

- `target_metadata`: Target information and scope verification
- `reconnaissance_map`: Live hosts, ports, endpoints discovered
- `vulnerability_journal`: Completed checks, active leads, findings
- `learning_patterns`: Cross-target pattern learning
- `session_state`: Current scanning session state
```
"""

    def add_context(
        self,
        target_id: str,
        scan_id: str,
        context_type: str,
        content: dict[str, Any],
        metadata: Optional[dict[str, Any]] = None
    ) -> None:
        """
        Add context entry to persistent storage

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            context_type: Type of context (target_metadata, reconnaissance_map, etc.)
            content: Context content
            metadata: Optional metadata (timestamp, source, etc.)
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target_id": target_id,
            "scan_id": scan_id,
            "context_type": context_type,
            "content": content,
            "metadata": metadata or {}
        }

        with self.lock:
            self._write_entry(entry)

    def _write_entry(self, entry: dict[str, Any]) -> None:
        """Write single entry to file"""
        header = self._get_context_header()
        header_exists = self.context_file.exists() and self.context_file.read_text(encoding='utf-8').startswith('# Matthunder AI Context')

        with self.context_file.open('a', encoding='utf-8') as f:
            if not header_exists:
                f.write(header + '\n')
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    async def add_context_async(
        self,
        target_id: str,
        scan_id: str,
        context_type: str,
        content: dict[str, Any],
        metadata: Optional[dict[str, Any]] = None
    ) -> None:
        """
        Async version of add_context - writes to file asynchronously

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            context_type: Type of context
            content: Context content
            metadata: Optional metadata
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "target_id": target_id,
            "scan_id": scan_id,
            "context_type": context_type,
            "content": content,
            "metadata": metadata or {}
        }

        async with aiofiles.open(self.context_file, 'a', encoding='utf-8') as f:
            header = self._get_context_header()
            header_exists = await f.read(100) if self.context_file.exists() else False

            if header_exists and not header_exists.startswith('# Matthunder AI Context'):
                await f.write(header + '\n')
            await f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    def get_target_context(self, target_id: str) -> List[dict[str, Any]]:
        """
        Get all context entries for a target

        Args:
            target_id: Target domain or ID

        Returns:
            List of context entries
        """
        entries = []
        if not self.context_file.exists():
            return entries

        with self.context_file.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("target_id") == target_id:
                        entries.append(entry)
                except json.JSONDecodeError:
                    continue

        return entries

    def get_context_by_type(self, context_type: str) -> List[dict[str, Any]]:
        """
        Get all context entries of a specific type

        Args:
            context_type: Context type to filter by

        Returns:
            List of context entries
        """
        entries = []
        if not self.context_file.exists():
            return entries

        with self.context_file.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("context_type") == context_type:
                        entries.append(entry)
                except json.JSONDecodeError:
                    continue

        return entries

    def get_recent_context(self, limit: int = 10) -> List[dict[str, Any]]:
        """
        Get most recent context entries

        Args:
            limit: Maximum number of entries to return

        Returns:
            List of recent context entries
        """
        entries = []
        if not self.context_file.exists():
            return entries

        with self.context_file.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    entries.append(entry)
                except json.JSONDecodeError:
                    continue

        # Sort by timestamp descending
        entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return entries[:limit]

    def clear_target_context(self, target_id: str) -> None:
        """
        Clear all context entries for a target

        Args:
            target_id: Target domain or ID
        """
        if not self.context_file.exists():
            return

        with self.lock:
            temp_file = self.context_file.with_suffix('.tmp')
            with self.context_file.open('r', encoding='utf-8') as src:
                with temp_file.open('w', encoding='utf-8') as dst:
                    header = self._get_context_header()
                    dst.write(header + '\n')

                    for line in src:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            if entry.get("target_id") != target_id:
                                dst.write(line + '\n')
                        except json.JSONDecodeError:
                            continue

            temp_file.replace(self.context_file)

    def get_stats(self) -> dict[str, Any]:
        """
        Get memory statistics

        Returns:
            Dictionary with stats
        """
        stats = {
            "total_entries": 0,
            "targets": set(),
            "context_types": {},
            "last_updated": None
        }

        if not self.context_file.exists():
            return stats

        with self.context_file.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                stats["total_entries"] += 1

                try:
                    entry = json.loads(line)
                    stats["targets"].add(entry.get("target_id", "unknown"))

                    ct = entry.get("context_type", "unknown")
                    stats["context_types"][ct] = stats["context_types"].get(ct, 0) + 1

                    ts = entry.get("timestamp")
                    if ts and (not stats["last_updated"] or ts > stats["last_updated"]):
                        stats["last_updated"] = ts
                except json.JSONDecodeError:
                    continue

        return stats