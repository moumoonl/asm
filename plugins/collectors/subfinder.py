#!/usr/bin/env python3
"""subfinder collector:聚合被动子域(keyless)(§7)。"""
import json
import os
import re
import shutil
import subprocess
import sys

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
            p = subprocess.run([find_bin("subfinder"), "-d", root, "-silent",
                                "-max-time", "3"],
                               capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            print(f"[subfinder] {root} 超时", file=sys.stderr)
            continue
        seen = set()
        for name in p.stdout.splitlines():
            name = name.strip().lower().rstrip(".")
            if not name or name in seen or "*" in name:
                continue
            if not name.endswith(root) or not HOST_RE.match(name):
                continue
            seen.add(name)
            out = {"schema_version": 1, "kind": "asset", "type": "domain",
                   "value": name, "root": root, "origin": "enumerated",
                   "source": ["subfinder"], "attrs": {}}
            print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
