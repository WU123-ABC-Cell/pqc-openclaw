#!/usr/bin/env python3
"""Refuse a new fallback key when an existing state DB contains wrapped identities."""

import os
import sqlite3
import stat
import sys
from pathlib import Path


def may_create_wrap_key(database_path: str) -> bool:
    component = Path(database_path).absolute()
    while True:
        try:
            mode = os.lstat(component).st_mode
        except FileNotFoundError:
            parent = component.parent
            if parent == component:
                return True
            component = parent
            continue
        if stat.S_ISLNK(mode):
            # Inspect a resolved alias; never mistake a dangling link for fresh state.
            try:
                os.stat(component)
            except OSError as error:
                raise OSError("state database path contains an unresolved symbolic link") from error
        if component != Path(database_path).absolute():
            return True
        break
    database_uri = Path(database_path).resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(database_uri, uri=True) as database:
        table = database.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'device_identities'"
        ).fetchone()
        if table is None:
            return True
        columns = {
            row[1] for row in database.execute("PRAGMA table_info(device_identities)")
        }
        wrapped_columns = {
            "mldsa_private_key_wrapped",
            "mldsa_private_key_wrap_key_id",
        }
        legacy_columns = {
            "identity_key",
            "device_id",
            "public_key_pem",
            "private_key_pem",
            "created_at_ms",
            "updated_at_ms",
        }
        if not columns.intersection(wrapped_columns) and columns == legacy_columns:
            return True
        if not wrapped_columns.issubset(columns):
            raise sqlite3.DatabaseError("unrecognized device identity table schema")
        wrapped = database.execute(
            "SELECT 1 FROM device_identities "
            "WHERE mldsa_private_key_wrapped IS NOT NULL "
            "OR mldsa_private_key_wrap_key_id IS NOT NULL LIMIT 1"
        ).fetchone()
        return wrapped is None


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check-wrap-key-recovery.py STATE_DATABASE", file=sys.stderr)
        return 2
    try:
        safe = may_create_wrap_key(sys.argv[1])
    except (OSError, sqlite3.Error) as error:
        print(f"Cannot inspect existing state database: {error}", file=sys.stderr)
        return 2
    if not safe:
        print("Encrypted device identities exist; restore their original wrap key.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
