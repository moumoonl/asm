#!/usr/bin/env python3
"""gau collector:Wayback/CommonCrawl 历史 URL -> 归一到端点(路径存 attrs.paths)(§7)。"""
import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def find_bin(name: str) -> str:
    cand = os.path.join(os.environ.get("ASM_BIN_DIR", "."), name)
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    return shutil.which(name) or name


def main() -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        a = json.loads(line)
        root = a.get("root") or a["value"]
        try:
            p = subprocess.run([find_bin("gau"), "--subs", root],
                               capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            print(f"[gau] {root} 超时", file=sys.stderr)
            continue
        eps: dict[str, dict] = {}
        for u in p.stdout.splitlines():
            u = u.strip()
            if not u:
                continue
            try:
                sp = urlsplit(u)
            except ValueError:
                continue
            host = (sp.hostname or "").lower().rstrip(".")
            if not host or not host.endswith(root) or not HOST_RE.match(host):
                continue
            try:
                port = sp.port or (443 if sp.scheme == "https" else 80)
            except ValueError:
                continue
            key = f"{host}:{port}"
            e = eps.setdefault(key, {"paths": set(), "scheme": sp.scheme})
            if sp.path and sp.path != "/":
                e["paths"].add(sp.path[:120])
        for key, e in eps.items():
            out = {"schema_version": 1, "kind": "asset", "type": "endpoint",
                   "value": key, "root": root, "origin": "enumerated",
                   "source": ["gau"],
                   "attrs": {"scheme": e["scheme"],
                             "paths": sorted(e["paths"])[:50]}}
            print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
