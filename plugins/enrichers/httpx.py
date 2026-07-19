#!/usr/bin/env python3
"""httpx enricher:探活+富化一体(§7)。

输入 endpoint Asset JSONL;输出存活端点(富化 attrs)。死端点不输出(框架据此标 parked)。
一次探测产出:scheme/status/title/tech/webserver/is_login_page/behind_waf/ip/resp_sig/change_sig。
"""
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile

CFG = json.loads(os.environ.get("ASM_PLUGIN_CONFIG", "{}") or "{}")
TIMEOUT = int(CFG.get("timeout", 10))
RATE = int(CFG.get("rate", 50))
BODY_BYTES = int(CFG.get("resp_body_bytes", 8192))
NORMALIZE = bool(CFG.get("normalize_body", True))
WAF_DETECT = bool(CFG.get("detect", True))

WAF_HEADERS = re.compile(
    r"(cloudflare|cf-ray|x-waf|aliyunwaf|aliyun\.waf|sucuri|akamai|incapsula|"
    r"baiduyun|yunsuo|safedog|anquanbao|360wzws|knownsec|qcloud|tencentwaf|"
    r"huaweicloudwaf|aws.?waf|denyall|fortiweb|imperva)", re.I)

LOGIN_KW = re.compile(
    r"(登录|登陆|用户登录|管理平台|后台管理|login|sign[\s_-]?in|log[\s_-]?on|"
    r"password|passwd|username|admin\s*console|管理控制台)", re.I)

TS_RE = re.compile(r"\b1[0-9]{9,12}\b")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{24,}\b")
TOKEN_KV_RE = re.compile(
    r"((?:csrf|token|nonce|session|ticket|sid|auth)[\w\-]*\s*[=:]\s*[\"']?)[\w\-./+=]{6,}",
    re.I)
WS_RE = re.compile(r"\s+")


def find_bin(name: str) -> str:
    cand = os.path.join(os.environ.get("ASM_BIN_DIR", "."), name)
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    return shutil.which(name) or name


def load_waf_cidrs() -> list:
    path = os.path.join(os.environ.get("ASM_DATA_DIR", "."), "waf_ranges.yaml")
    nets = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"\s*-\s+([0-9a-fA-F.:]+/\d+)", line)
                if m:
                    try:
                        nets.append(ipaddress.ip_network(m.group(1), strict=False))
                    except ValueError:
                        pass
    except OSError:
        pass
    return nets


WAF_NETS = load_waf_cidrs() if WAF_DETECT else []


def ip_in_waf(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in WAF_NETS)


def norm_body(body: str) -> str:
    if not NORMALIZE:
        return body
    body = TS_RE.sub("TS", body)
    body = UUID_RE.sub("UUID", body)
    body = HEX_RE.sub("HEX", body)
    body = TOKEN_KV_RE.sub(r"\1X", body)
    return WS_RE.sub(" ", body)


def sig(status, title, tech, body) -> tuple[str, str]:
    t = ",".join(sorted(tech or []))
    change = hashlib.sha256(f"{status}|{title}|{t}".encode()).hexdigest()[:16]
    resp = hashlib.sha256(
        f"{status}|{title}|{norm_body(body)}|{t}".encode()).hexdigest()[:16]
    return resp, change


def waf_of(raw_head: str, tech: list, ip: str) -> str:
    m = WAF_HEADERS.search(raw_head or "")
    if m:
        return m.group(1).lower()
    for t in tech or []:
        if WAF_HEADERS.search(t):
            return t.lower()
    if ip and ip_in_waf(ip):
        return "waf-cidr"
    return ""


def main() -> int:
    assets = [json.loads(l) for l in sys.stdin if l.strip()]
    if not assets:
        return 0
    probes = {}   # url -> (idx, is_path_probe)
    for i, a in enumerate(assets):
        scheme = (a.get("attrs") or {}).get("scheme") or ""
        target = f"{scheme}://{a['value']}" if scheme else a["value"]
        probes[target] = (i, False)
        paths = (a.get("attrs") or {}).get("paths") or []
        if scheme and paths and paths[0] not in ("", "/"):
            probes[f"{scheme}://{a['value']}{paths[0]}"] = (i, True)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(probes))
        list_file = tf.name
    cmd = [find_bin("httpx"), "-l", list_file, "-json", "-irr",
           "-status-code", "-title", "-tech-detect", "-web-server",
           "-follow-redirects", "-timeout", str(TIMEOUT), "-retries", "1",
           "-threads", "50", "-rate-limit", str(RATE), "-silent", "-no-color"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT * max(len(probes), 2) + 120)
    finally:
        os.unlink(list_file)
    enriched: dict[int, dict] = {}
    for line in p.stdout.splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = r.get("input") or r.get("url") or ""
        # httpx 的 input 字段回显原始输入;失败时退回 url 规范化匹配
        idx_pair = probes.get(key)
        if idx_pair is None:
            continue
        idx, is_path = idx_pair
        raw = r.get("response") or ""
        head, _, body = raw.partition("\r\n\r\n")
        status = r.get("status_code") or 0
        title = (r.get("title") or "").strip()
        tech = r.get("tech") or []
        body_head = body[:BODY_BYTES]
        e = enriched.setdefault(idx, {"main": None, "path": None})
        entry = {"status": status, "title": title, "tech": tech,
                 "webserver": r.get("webserver") or "",
                 "scheme": r.get("scheme") or "",
                 "raw_head": head, "body": body_head}
        if is_path:
            e["path"] = entry
        else:
            e["main"] = entry
    out = []
    for i, a in enumerate(assets):
        e = enriched.get(i)
        if not e or not e["main"]:
            continue  # 死端点:不输出
        m = e["main"]
        host = a["value"].rsplit(":", 1)[0]
        try:
            ip = socket.gethostbyname(host)
        except (socket.gaierror, UnicodeError):
            ip = ""
        resp_sig, change_sig = sig(m["status"], m["title"], m["tech"], m["body"])
        behind = waf_of(m["raw_head"], m["tech"], ip)
        login_text = m["title"] + " " + m["body"][:4096]
        attrs = dict(a.get("attrs") or {})
        attrs.update({
            "scheme": m["scheme"], "status": m["status"], "title": m["title"],
            "tech": m["tech"], "webserver": m["webserver"],
            "is_login_page": bool(LOGIN_KW.search(login_text)),
            "behind_waf": behind, "ip": ip,
            "resp_sig": resp_sig, "change_sig": change_sig,
        })
        if e.get("path"):
            attrs["path_status"] = e["path"]["status"]
            attrs["path_title"] = e["path"]["title"]
        a["attrs"] = attrs
        a["type"] = "endpoint"
        a.setdefault("source", [])
        if "httpx" not in a["source"]:
            a["source"] = a["source"] + ["httpx"]
        out.append(a)
    for a in out:
        print(json.dumps(a, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
