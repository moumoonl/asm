#!/usr/bin/env python3
"""stdout notifier:CLI 兜底输出(§13)。"""
import json
import sys

for line in sys.stdin:
    if not line.strip():
        continue
    msg = json.loads(line)
    print(msg.get("text", ""))
sys.exit(0)
