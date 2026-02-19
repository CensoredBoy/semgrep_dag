"""
Database initialization and session management.

Usage:
    from scanner.data.database import init_db, get_session

    # Initialize (creates tables if not exist)
    engine = init_db("sqlite:///scanner.db")

    # Get a session
    with get_session(engine) as session:
        session.add(...)
        session.commit()
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from scanner.data.models import Base


def _set_sqlite_pragmas(dbapi_connection, connection_record):  # noqa: ANN001, ANN201
    """Enable WAL mode and foreign keys for SQLite."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode = WAL")
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.close()


def init_db(url: str = "sqlite:///scanner.db", echo: bool = False) -> Engine:
    """
    Create engine, apply pragmas, create all tables.

    Args:
        url: SQLAlchemy database URL. Defaults to local SQLite file.
        echo: If True, log all SQL statements.

    Returns:
        Configured SQLAlchemy Engine.
    """
    engine = create_engine(url, echo=echo)

    # SQLite-specific pragmas
    if url.startswith("sqlite"):
        event.listen(engine, "connect", _set_sqlite_pragmas)

    # Create all tables from ORM metadata
    Base.metadata.create_all(engine)

    return engine


def get_session(engine: Engine) -> Session:
    """
    Create a new SQLAlchemy session.

    Usage:
        with get_session(engine) as session:
            ...
    """
    factory = sessionmaker(bind=engine)
    return factory()


def init_db_from_sql(db_path: str, sql_path: str) -> None:
    """
    Apply raw SQL migration to a SQLite database.

    Args:
        db_path: Path to SQLite database file.
        sql_path: Path to .sql migration file.
    """
    import sqlite3

    sql = Path(sql_path).read_text(encoding="utf-8")
    conn = sqlite3.connect(db_path)
    conn.executescript(sql)
    conn.close()
