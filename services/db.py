import sqlite3
import queue
import threading
import time
import os
import logging

logger = logging.getLogger('ippel.services.db')

DB_PATH = 'ippel_system.db'

# Global connection pool
_db_pool_size = 150
_db_pool: 'queue.Queue[sqlite3.Connection]' = queue.Queue(maxsize=_db_pool_size)
_pool_lock = threading.Lock()


def _new_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    # CRITICAL: Configure UTF-8 encoding to handle accents correctly
    conn.text_factory = str
    conn.execute('PRAGMA encoding="UTF-8"')
    # Performance pragmas
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA cache_size=10000')
    conn.execute('PRAGMA temp_store=MEMORY')
    conn.execute('PRAGMA mmap_size=268435456')
    return conn


def warm_pool(size: int = _db_pool_size) -> None:
    with _pool_lock:
        try:
            current = _db_pool.qsize()
        except Exception:
            current = 0
        target = min(size, _db_pool_size)
        for _ in range(max(0, target - current)):
            try:
                _db_pool.put_nowait(_new_connection())
            except Exception:
                break


def get_db_connection() -> sqlite3.Connection:
    try:
        return _db_pool.get_nowait()
    except queue.Empty:
        return _new_connection()


def return_db_connection(conn: sqlite3.Connection) -> None:
    try:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
            _db_pool.put_nowait(conn)
    except queue.Full:
        try:
            conn.close()
        except Exception:
            pass
