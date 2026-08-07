"""Apply db/schema.sql to the CockroachDB cluster.

Run once after creating the cluster:
    python scripts/migrate.py

Safe to re-run: CockroachDB's CREATE TABLE IF NOT EXISTS semantics mean
existing tables are left intact. CREATE TYPE will error if the type already
exists — comment those out on re-runs, or use the --skip-types flag.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "db" / "schema.sql"

# Statements that are safe to skip on re-runs (type already exists error)
_TYPE_PREFIXES = ("CREATE TYPE",)


def split_statements(sql: str) -> list[str]:
    """Split SQL on semicolons, skipping comments and blank lines."""
    stmts = []
    current: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.startswith("--") or not stripped:
            current.append(line)
            continue
        current.append(line)
        if stripped.endswith(";"):
            stmt = "\n".join(current).strip().rstrip(";").strip()
            if stmt:
                stmts.append(stmt)
            current = []
    return stmts


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply Sentinel schema to CockroachDB")
    parser.add_argument("--skip-types", action="store_true", help="Skip CREATE TYPE statements")
    parser.add_argument("--dry-run", action="store_true", help="Print statements without executing")
    args = parser.parse_args()

    # Load env
    sys.path.insert(0, str(ROOT / "backend"))
    from app.config import settings  # noqa: E402

    if not settings.database_url:
        print("DATABASE_URL is not set. Copy .env.example to .env and fill it in.")
        return 1

    sql = SCHEMA.read_text(encoding="utf-8")
    statements = split_statements(sql)

    print(f"Applying {len(statements)} statements to {settings.database_url[:40]}…\n")

    with psycopg.connect(settings.database_url) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            ok = 0
            skip = 0
            errors = 0
            for stmt in statements:
                first_line = stmt.lstrip().splitlines()[0][:60]
                if args.skip_types and any(stmt.upper().startswith(p) for p in _TYPE_PREFIXES):
                    print(f"  SKIP  {first_line}")
                    skip += 1
                    continue
                if args.dry_run:
                    print(f"  DRY   {first_line}")
                    ok += 1
                    continue
                try:
                    cur.execute(stmt)
                    print(f"  OK    {first_line}")
                    ok += 1
                except psycopg.errors.DuplicateObject:
                    print(f"  EXISTS {first_line}")
                    skip += 1
                except psycopg.errors.DuplicateTable:
                    print(f"  EXISTS {first_line}")
                    skip += 1
                except Exception as exc:
                    print(f"  ERROR {first_line}\n        {exc}")
                    errors += 1

    print(f"\n{ok} applied, {skip} skipped, {errors} errors")
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
