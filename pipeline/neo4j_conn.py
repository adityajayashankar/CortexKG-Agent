"""
pipeline/neo4j_conn.py
----------------------
Shared Neo4j driver singleton with graceful lifecycle management.

All code that needs Neo4j should import from here:
    from pipeline.neo4j_conn import get_neo4j_driver

This eliminates the duplicate singleton + connection leak problem where
both tools.py and retriever.py each created their own driver with no
atexit cleanup.
"""

import atexit
import os
import threading

_lock = threading.Lock()
_driver = None
_closed = False
_atexit_registered = False

# Connections idle for longer than this (seconds) are refreshed by the pool.
_MAX_CONN_LIFETIME = int(os.getenv("NEO4J_MAX_CONN_LIFETIME", "300"))


def _is_production_mode() -> bool:
    return os.getenv("APP_ENV", "").strip().lower() in {"prod", "production"}


def _create_driver():
    """Create a fresh Neo4j driver. Returns None on failure."""
    try:
        from neo4j import GraphDatabase
    except ImportError:
        print("[neo4j_conn] neo4j package not installed — KG tools will use JSON fallback.")
        return None

    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "").strip()
    if not password:
        if _is_production_mode():
            raise RuntimeError("NEO4J_PASSWORD is required in production mode.")
        return None

    try:
        driver = GraphDatabase.driver(
            uri,
            auth=(user, password),
            max_connection_lifetime=_MAX_CONN_LIFETIME,
            keep_alive=True,
        )
        with driver.session() as s:
            s.run("RETURN 1").consume()
        return driver
    except Exception as e:
        print(f"[neo4j_conn] Neo4j unavailable ({e}) — KG tools will use JSON fallback.")
        return None


def get_neo4j_driver():
    """
    Return the shared Neo4j driver, creating it lazily.
    Does NOT ping on every call — the connection pool handles keepalive.
    Call reset_driver() if you catch a DriverError and want to reconnect.
    """
    global _driver, _closed, _atexit_registered
    if _closed:
        return None
    if _driver is not None:
        return _driver

    with _lock:
        if _driver is not None:
            return _driver
        if _closed:
            return None
        _driver = _create_driver()
        if _driver is not None and not _atexit_registered:
            atexit.register(_close_driver)
            _atexit_registered = True
        return _driver


def reset_driver():
    """
    Discard the current driver and reconnect.
    Call this when a query raises 'Driver closed' or similar stale-connection errors.
    Returns the new driver (or None if reconnection fails).
    """
    global _driver, _closed, _atexit_registered
    if _closed:
        return None
    with _lock:
        if _closed:
            return None
        if _driver is not None:
            try:
                _driver.close()
            except Exception:
                pass
            _driver = None
        _driver = _create_driver()
        if _driver is not None and not _atexit_registered:
            atexit.register(_close_driver)
            _atexit_registered = True
        return _driver


def _close_driver():
    """atexit handler — safely close the shared driver."""
    global _driver, _closed
    _closed = True
    if _driver is not None:
        try:
            _driver.close()
        except Exception:
            pass
        _driver = None
