#!/usr/bin/env python3
"""js_secrets enricher(叶子):katana 抓存活端点 JS -> 密钥/引用 Finding(§7)。

Finding 不转 Asset、不派生、不回灌。密钥打码后输出。引用类只保留非公开(内网 IP/主机名)。
"""
import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

CFG = json.loads(os.environ.get("ASM_PLUGIN_CONFIG", "{}") or "{}")
MAX_JS = int(CFG.get("max_js", 60))
MAX_EPS = int(CFG.get("max_endpoints", 40))
EP_WORKERS = int(CFG.get("endpoint_workers", 4))
JS_WORKERS = int(CFG.get("js_workers", 8))
KATANA_TIMEOUT = int(CFG.get("katana_timeout", 120))
FETCH_TIMEOUT = 6
MAX_BYTES = 2 * 1024 * 1024

SECRET_RULES = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("aws-secret-key", re.compile(r"(?i)aws.{0,20}secret.{0,5}['\"=:\s]+([A-Za-z0-9/+=]{40})"), "high"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "medium"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("generic-secret", re.compile(
        r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)"
        r"['\"\s:=]{1,6}['\"]([A-Za-z0-9\-_./+=]{8,64})['\"]"), "medium"),
]
URL_RE = re.compile(r"https?://[^\s\"'<>)\\]{4,200}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
JS_RE = re.compile(r"\.js($|\?)", re.I)


def find_bin(name: str) -> str:
    cand = os.path.join(os.environ.get("ASM_BIN_DIR", "."), name)
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    return shutil.which(name) or name


def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return False


def mask(s: str) -> str:
    return s[:4] + "****" if len(s) > 8 else "****"


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "asm-js/1.0"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
        return r.read(MAX_BYTES).decode("utf-8", errors="replace")


def katana_js(base: str) -> list[str]:
    cmd = [find_bin("katana"), "-u", base, "-d", "2", "-jc", "-silent",
           "-timeout", "15", "-c", "5", "-rate-limit", "20", "-no-color"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=KATANA_TIMEOUT)
    except subprocess.TimeoutExpired:
        return []
    urls = [u.strip() for u in p.stdout.splitlines() if JS_RE.search(u.strip())]
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
        if len(out) >= MAX_JS:
            break
    return out


def scan_js(text: str, js_url: str, root: str, findings: list, seen: set) -> None:
    for rule, rx, sev in SECRET_RULES:
        for m in rx.finditer(text):
            raw = m.group(0)
            val = f"[{rule}] {mask(raw)} 见 {js_url}"
            if val in seen:
                continue
            seen.add(val)
            findings.append({"schema_version": 1, "kind": "finding", "type": "leaked_secret",
                             "value": val, "root": root, "source": ["js_secrets"],
                             "severity": sev,
                             "evidence": f"规则 {rule},命中 {mask(raw)},长度 {len(raw)}"})
            break  # 同规则同文件一条就够
    # js_reference:非公开引用(内网 IP / 内网主机名)
    for ip in set(IP_RE.findall(text)):
        if is_private_ip(ip):
            val = f"{ip} 见 {js_url}"
            if val not in seen:
                seen.add(val)
                findings.append({"schema_version": 1, "kind": "finding", "type": "js_reference",
                                 "value": val, "root": root, "source": ["js_secrets"],
                                 "severity": "info", "evidence": "内网 IP 引用"})
    for u in set(URL_RE.findall(text)):
        try:
            h = (urlsplit(u).hostname or "").lower()
        except ValueError:
            continue
        if not h:
            continue
        if is_private_ip(h) or "." not in h or h.endswith(
                (".internal", ".local", ".lan", ".corp", ".intra")):
            val = f"{u[:120]} 见 {js_url}"
            if val not in seen:
                seen.add(val)
                findings.append({"schema_version": 1, "kind": "finding", "type": "js_reference",
                                 "value": val, "root": root, "source": ["js_secrets"],
                                 "severity": "info", "evidence": "内网/非公开主机引用"})


def scan_endpoint(a: dict) -> list:
    """单端点:katana 发现 JS -> 并发抓 JS -> 扫密钥/引用。返回本端点 findings。"""
    scheme = (a.get("attrs") or {}).get("scheme") or "https"
    base = f"{scheme}://{a['value']}"
    root = a.get("root", "") or a["value"].rsplit(":", 1)[0]
    findings: list = []
    seen: set = set()
    js_urls = katana_js(base)
    if not js_urls:
        return findings
    with ThreadPoolExecutor(max_workers=JS_WORKERS) as ex:
        futs = {ex.submit(fetch, u): u for u in js_urls}
        for fut in as_completed(futs):
            u = futs[fut]
            try:
                text = fut.result()
            except Exception:
                continue
            scan_js(text, u, root, findings, seen)
    return findings


def main() -> int:
    assets = [json.loads(l) for l in sys.stdin if l.strip()]
    assets = assets[:MAX_EPS]
    lock = threading.Lock()

    def emit(fs: list) -> None:
        if not fs:
            return
        with lock:
            for f in fs:
                print(json.dumps(f, ensure_ascii=False))
            sys.stdout.flush()  # 边跑边出,框架超时也能回收部分结果

    with ThreadPoolExecutor(max_workers=EP_WORKERS) as ex:
        futs = {ex.submit(scan_endpoint, a): a for a in assets}
        for fut in as_completed(futs):
            a = futs[fut]
            try:
                emit(fut.result())
            except Exception as e:
                print(f"[js_secrets] {a.get('value')} 扫描异常: {e}",
                      file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
