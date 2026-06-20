import sqlite3

import pytest

from matthunder_core.registry import canonical_key, list_scanners
from matthunder_core.scope import ScopeError, validate_target
from scanners import common


def test_scope_gate_blocks_local_targets():
    with pytest.raises(ScopeError):
        validate_target("127.0.0.1")


def test_registry_canonical_aliases():
    assert canonical_key("deep") == "dps"
    assert canonical_key("thirdparty") == "tpa"
    assert any(item.key == "blh" for item in list_scanners())


def test_sqlite_schema_has_progress_columns(tmp_path, monkeypatch):
    db_path = tmp_path / "matthunder_scans.db"
    monkeypatch.setattr(common, "DB_PATH", str(db_path))
    con = common.open_db()
    try:
        columns = {row["name"] for row in con.execute("PRAGMA table_info(scans)").fetchall()}
    finally:
        con.close()

    assert {"progress_pct", "current_stage", "error_message"}.issubset(columns)
