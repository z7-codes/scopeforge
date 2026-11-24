from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

TABLES = {"urls", "findings"}


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS urls(
                id INTEGER PRIMARY KEY, url TEXT UNIQUE, src TEXT,
                status INT, length INT, seen INT DEFAULT 0);
            CREATE TABLE IF NOT EXISTS findings(
                id INTEGER PRIMARY KEY, url TEXT, param TEXT, category TEXT,
                payload TEXT, confidence INT, signals TEXT, evidence TEXT, advice TEXT,
                ts TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(url, param, category, payload));
            """
        )

    def add_url(self, url: str, src: str) -> bool:
        with self.lock:
            try:
                self.db.execute("INSERT INTO urls(url,src) VALUES(?,?)", (url, src))
                self.db.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def urls(self) -> list[tuple[int, str]]:
        with self.lock:
            return list(self.db.execute("SELECT id,url FROM urls"))

    def add_finding(self, **values: object) -> bool:
        with self.lock:
            try:
                self.db.execute(
                    "INSERT INTO findings(url,param,category,payload,confidence,signals,evidence,advice)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    (
                        values["url"],
                        values["param"],
                        values["category"],
                        values["payload"],
                        values["confidence"],
                        json.dumps(values["signals"]),
                        values["evidence"],
                        values.get("advice", ""),
                    ),
                )
                self.db.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def findings(self) -> list[tuple[object, ...]]:
        with self.lock:
            return list(self.db.execute("SELECT * FROM findings ORDER BY confidence DESC, id"))

    def count(self, table: str) -> int:
        if table not in TABLES:
            raise ValueError(f"unknown table: {table}")
        with self.lock:
            row = self.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            return int(row[0])

    def close(self) -> None:
        with self.lock:
            self.db.close()
