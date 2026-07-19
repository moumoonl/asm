"""增量状态:sqlite 双表(seen 端点+finding / seeds 主机种子)+ 单实例 flock(§9.1)。

seen 只存指纹/签名/状态标记;value 列对端点存 host:port(复探需要),对 finding 存已打码展示值。
不存标题原文、不存密钥、不存业务数据。删了 state.db 只是全量重推。
"""
from __future__ import annotations

import fcntl
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen(
  fp TEXT PRIMARY KEY,
  kind TEXT,                    -- endpoint | finding
  type TEXT,
  value TEXT,                   -- 端点=host:port;finding=打码展示值
  root TEXT,
  state TEXT,                   -- live | parked(finding 记 '-')
  last_sig TEXT,
  first_seen INT, last_seen INT,
  last_probe INT,
  notified INT DEFAULT 0,
  cooldown_until INT DEFAULT 0
);
CREATE TABLE IF NOT EXISTS seeds(
  host TEXT PRIMARY KEY,
  root TEXT,
  last_naabu INT DEFAULT 0,
  last_collect INT DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"""


class StateLock:
    """flock 单实例锁:拿不到锁直接报错退出(防 timer 与手动 run 并发写库/重复通知)。"""

    def __init__(self, root: str):
        self.path = os.path.join(root, "state.db.lock")
        self.fd = None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            self.fd = None
            raise SystemExit("[asm] 另一个 asm run 正在运行(锁占用),本次退出。")
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)


class State:
    def __init__(self, root: str, db_path: str):
        self.root = root
        self.db = sqlite3.connect(os.path.join(root, db_path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ---------- meta ----------
    def meta_get(self, k: str, default: str = "") -> str:
        r = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r["v"] if r else default

    def meta_set(self, k: str, v: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", (k, v))
        self.db.commit()

    def next_round(self) -> int:
        r = int(self.meta_get("round", "0") or 0) + 1
        self.meta_set("round", str(r))
        return r

    # ---------- seen ----------
    def seen_get(self, fp: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM seen WHERE fp=?", (fp,)).fetchone()

    def seen_upsert(self, fp: str, kind: str, type_: str, value: str, root: str = "",
                    state: str = "-", last_sig: str | None = None,
                    notified: int = 0, cooldown_until: int = 0) -> None:
        now = int(time.time())
        old = self.seen_get(fp)
        if old:
            self.db.execute(
                "UPDATE seen SET last_seen=?, state=?, last_sig=COALESCE(?,last_sig), "
                "notified=?, cooldown_until=? WHERE fp=?",
                (now, state, last_sig, notified, cooldown_until, fp))
        else:
            self.db.execute(
                "INSERT INTO seen(fp,kind,type,value,root,state,last_sig,first_seen,last_seen,"
                "last_probe,notified,cooldown_until) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (fp, kind, type_, value, root, state, last_sig, now, now, 0, notified,
                 cooldown_until))
        self.db.commit()

    def seen_touch(self, fp: str, probed: bool = False) -> None:
        now = int(time.time())
        if probed:
            self.db.execute("UPDATE seen SET last_seen=?, last_probe=? WHERE fp=?",
                            (now, now, fp))
        else:
            self.db.execute("UPDATE seen SET last_seen=? WHERE fp=?", (now, fp))
        self.db.commit()

    def seen_endpoints(self, states: tuple[str, ...] = ("live", "parked")) -> list[sqlite3.Row]:
        q = ",".join("?" * len(states))
        return list(self.db.execute(
            f"SELECT * FROM seen WHERE kind='endpoint' AND state IN ({q})", states))

    def purge(self, days: int) -> int:
        cutoff = int(time.time()) - days * 86400
        cur = self.db.execute("DELETE FROM seen WHERE last_seen<?", (cutoff,))
        self.db.commit()
        return cur.rowcount

    def purge_target(self, host_or_root: str) -> int:
        n = 0
        for sql, arg in (
            ("DELETE FROM seeds WHERE host=? OR root=?", (host_or_root, host_or_root)),
            ("DELETE FROM seen WHERE value LIKE ? OR root=?",
             (f"{host_or_root}:%", host_or_root)),
            ("DELETE FROM seen WHERE value LIKE ?", (f"%.{host_or_root}:%",)),
        ):
            n += self.db.execute(sql, arg).rowcount
        self.db.commit()
        return n

    # ---------- seeds ----------
    def seed_get(self, host: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM seeds WHERE host=?", (host,)).fetchone()

    def seed_upsert(self, host: str, root: str = "", naabu: bool = False,
                    collect: bool = False) -> None:
        now = int(time.time())
        old = self.seed_get(host)
        if old:
            self.db.execute(
                "UPDATE seeds SET last_naabu=MAX(last_naabu,?), last_collect=MAX(last_collect,?) "
                "WHERE host=?",
                (now if naabu else 0, now if collect else 0, host))
        else:
            self.db.execute(
                "INSERT INTO seeds(host,root,last_naabu,last_collect) VALUES(?,?,?,?)",
                (host, root, now if naabu else 0, now if collect else 0))
        self.db.commit()

    def seeds_all(self) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT * FROM seeds"))

    def close(self) -> None:
        self.db.close()
