#!/usr/bin/env python3
"""naabu enricher:主机种子 -> 开放端口候选端点(§7)。

只扫 origin=user 种子;top-1000;WAF edge 跳过;输出候选端点(框架查重后交 httpx 验证)。
connect 扫描,无需 root。
"""
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys

CFG = json.loads(os.environ.get("ASM_PLUGIN_CONFIG", "{}") or "{}")
PORTS = str(CFG.get("ports", "top-1000"))
SKIP_WAF = bool(CFG.get("skip_waf_edge", True))


def find_bin(name: str) -> str:
    cand = os.path.join(os.environ.get("ASM_BIN_DIR", "."), name)
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    return shutil.which(name) or name


def load_waf_cidrs() -> list:
    nets = []
    path = os.path.join(os.environ.get("ASM_DATA_DIR", "."), "waf_ranges.yaml")
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


def emit(line: str, seed_map: dict) -> None:
    line = line.strip()
    if ":" not in line:
        return
    host, _, port = line.rpartition(":")
    if not port.isdigit():
        return
    base = seed_map.get(host, {})
    out = {"schema_version": 1, "kind": "asset", "type": "endpoint",
           "value": f"{host}:{int(port)}", "root": base.get("root", ""),
           "origin": "enumerated", "source": ["naabu"], "attrs": {}}
    print(json.dumps(out, ensure_ascii=False), flush=True)


def main() -> int:
    seeds = [json.loads(l) for l in sys.stdin if l.strip()]
    if not seeds:
        return 0
    nets = load_waf_cidrs()
    hosts = []
    for s in seeds:
        host = s["value"]
        try:
            ip = socket.gethostbyname(host)
        except (socket.gaierror, UnicodeError):
            print(f"[naabu] 解析失败 {host}", file=sys.stderr)
            continue
        if SKIP_WAF and nets:
            try:
                addr = ipaddress.ip_address(ip)
                if any(addr in n for n in nets):
                    print(f"[naabu] {host}({ip}) 命中 WAF 段,跳过", file=sys.stderr)
                    continue
            except ValueError:
                pass
        hosts.append(host)
    if not hosts:
        return 0
    top = PORTS.replace("top-", "") if PORTS.startswith("top-") else "1000"
    seed_map = {s["value"]: s for s in seeds}
    # 单主机逐个扫:每台独享超时预算,一台慢/卡只丢自己,不影响其它台。
    # host_timeout 是 hang 兜底(正常 top-1000 远不到此上限);0=不限,等 naabu 自己跑完。
    HOST_TIMEOUT = int(CFG.get("host_timeout", 600))
    RATE = str(CFG.get("rate", 1000))
    PROBE_TO = str(int(CFG.get("probe_timeout_ms", 2000)))
    RETRIES = str(int(CFG.get("retries", 1)))
    sub_to = HOST_TIMEOUT if HOST_TIMEOUT > 0 else None
    for host in hosts:
        cmd = [find_bin("naabu"), "-host", host, "-top-ports", top,
               "-s", "c", "-silent", "-timeout", PROBE_TO, "-rate", RATE,
               "-retries", RETRIES]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=sub_to)
            if p.returncode != 0 and not p.stdout:
                print(f"[naabu] {host} 退出码 {p.returncode}: {p.stderr[-200:]}",
                      file=sys.stderr)
            out_text = p.stdout
        except subprocess.TimeoutExpired as e:
            print(f"[naabu] {host} 超时({HOST_TIMEOUT}s,疑卡死),保留已扫出结果",
                  file=sys.stderr)
            out_text = e.stdout or ""
            if isinstance(out_text, bytes):
                out_text = out_text.decode("utf-8", errors="replace")
        for line in out_text.splitlines():
            emit(line, seed_map)
    return 0


if __name__ == "__main__":
    sys.exit(main())
