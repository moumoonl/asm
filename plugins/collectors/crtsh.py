#!/usr/bin/env python3
"""crtsh collector:CT 证书子域(通配过滤)(§7)。免费无 key。

crt.sh 服务端间歇 502/503/504/404/超时/半截 JSON,加**重试+指数退避**稳化(批量友好)。
配置(collectors.crtsh):retries(默认3) timeout(默认25s) backoff(默认2s)
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CFG = json.loads(os.environ.get("ASM_PLUGIN_CONFIG", "{}") or "{}")
RETRIES = int(CFG.get("retries", 3))
TIMEOUT = int(CFG.get("timeout", 25))
BACKOFF = float(CFG.get("backoff", 2.0))

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _retryable(e: Exception) -> bool:
    """crt.sh 的 502/503/504/404/500/超时/JSON 解析失败 视为瞬态可重试。"""
    if isinstance(e, urllib.error.HTTPError) and e.code in (404, 500, 502, 503, 504):
        return True
    if isinstance(e, (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ConnectionError)):
        return True
    return False


def query(root: str) -> list:
    q = urllib.parse.quote(f"%.{root}")
    url = f"https://crt.sh/?q={q}&output=json"
    last_err: Exception | None = None
    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "asm-crtsh/1.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except Exception as e:
            last_err = e
            if not _retryable(e) or attempt == RETRIES:
                raise
            time.sleep(BACKOFF * (2 ** (attempt - 1)))  # 2s, 4s, 8s...
    assert last_err is not None
    raise last_err  # 不可达


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        a = json.loads(line)
        root = a.get("root") or a["value"]
        try:
            data = query(root)
        except Exception as e:
            print(f"[crtsh] {root} 查询失败(已重试 {RETRIES} 次): {e}", file=sys.stderr)
            continue
        seen = set()
        for row in data:
            for name in str(row.get("name_value", "")).split("\n"):
                name = name.strip().lower().rstrip(".")
                if not name or "*" in name:  # 通配证书过滤
                    continue
                if not name.endswith(root) or not HOST_RE.match(name):
                    continue
                if name in seen:
                    continue
                seen.add(name)
                out = {"schema_version": 1, "kind": "asset", "type": "domain",
                       "value": name, "root": root, "origin": "enumerated",
                       "source": ["crtsh"], "attrs": {}}
                print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
