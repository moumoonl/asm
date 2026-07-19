#!/usr/bin/env python3
"""dingtalk notifier:markdown 推送(加签可选),单条 ≤100 行超出拆条(§13)。"""
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.parse
import urllib.request


def send(webhook: str, text: str) -> tuple[bool, str]:
    body = json.dumps({"msgtype": "markdown",
                       "markdown": {"title": "资产监控", "text": text}},
                      ensure_ascii=False).encode()
    req = urllib.request.Request(webhook, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            resp = json.loads(r.read().decode())
            return resp.get("errcode") == 0, str(resp)
    except Exception as e:
        return False, str(e)


def main() -> int:
    ok_all = True
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        text = msg.get("text", "")
        push = msg.get("push") or {}
        webhook = push.get("webhook", "")
        secret = push.get("secret", "")
        if not webhook:
            print("[dingtalk] webhook 为空", file=sys.stderr)
            return 1
        if secret:
            ts = str(round(time.time() * 1000))
            sign = urllib.parse.quote_plus(base64.b64encode(
                hmac.new(secret.encode(), f"{ts}\n{secret}".encode(),
                         hashlib.sha256).digest()))
            sep = "&" if "?" in webhook else "?"
            webhook = f"{webhook}{sep}timestamp={ts}&sign={sign}"
        lines = text.splitlines()
        for i in range(0, len(lines), 100):
            chunk = "\n".join(lines[i:i + 100])
            ok, resp = send(webhook, chunk)
            if not ok:
                print(f"[dingtalk] 发送失败: {resp}", file=sys.stderr)
                ok_all = False
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
