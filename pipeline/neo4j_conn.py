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


def _is_production_mode() -> bool:
    return os.getenv("APP_ENV", "").strip().lower() in {"prod", "production"}


def get_neo4j_driver():
    """
    Lazily initialise the Neo4j driver. Returns None if unavailable.
    Thread-safe, with atexit cleanup registered on first successful connect.
    """
    global _driver, _closed
    if _closed:
        return None
    if _driver is not None:
        return _driver

    with _lock:
        # Double-check after acquiring lock
        if _driver is not None:
            return _driver
        if _closed:
            return None

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
            driver = GraphDatabase.driver(uri, auth=(user, password))
            # Quick connectivity test
            with driver.session() as s:
                s.run("RETURN 1")
            _driver = driver
            atexit.register(_close_driver)
            return _driver
        except Exception as e:
            print(f"[neo4j_conn] Neo4j unavailable ({e}) — KG tools will use JSON fallback.")
            return None


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
