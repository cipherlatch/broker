"""Run Alembic migrations, stamping pre-Alembic (Phase 1) databases first.

Used by the container entrypoint: python -m scripts.migrate
"""

from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text

from app.db import get_engine

ROOT = Path(__file__).resolve().parent.parent
_LOCK_ID = 727_442_226  # arbitrary constant shared by all replicas


@contextmanager
def migration_lock():
    """Serialize migrations across replicas via a Postgres advisory lock, so
    N containers starting at once run the upgrade exactly once."""
    engine = get_engine()
    if engine.dialect.name != "postgresql":
        yield
        return
    with engine.connect() as conn:
        conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": _LOCK_ID})
        try:
            yield
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": _LOCK_ID})


def main() -> None:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))

    with migration_lock():
        tables = set(inspect(get_engine()).get_table_names())
        if "agents" in tables and "alembic_version" not in tables:
            # Existing Phase 1 database created via create_all: adopt it.
            print("migrate: pre-Alembic database detected, stamping baseline 0001")
            command.stamp(cfg, "0001")

        command.upgrade(cfg, "head")
    print("migrate: schema is up to date")


if __name__ == "__main__":
    main()
