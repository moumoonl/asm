#!/usr/bin/env python3
"""crtsh collector:CT 证书子域(通配过滤)(§7)。免费无 key。"""
import json
import os
import re
import sys
import urllib.request
import urllib.parse

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        a = json.loads(line)
        root = a.get("root") or a["value"]
        q = urllib.parse.quote(f"%.{root}")
        url = f"https://crt.sh/?q={q}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "asm-crtsh/1.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read().decode("utf-8", errors="replace"))
        except Exception as e:
            print(f"[crtsh] {root} 查询失败: {e}", file=sys.stderr)
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
