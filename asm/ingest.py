"""输入摄入:两段清洗 + 六种形态判定 + 派生 + PSL 根域守卫(§4)。

第一段代码精准判型(90%+);判不出的残渣交 LLM 兜底(§8A);修不回的写 rejected 日志,永不静默丢弃。
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from urllib.parse import urlsplit

import tldextract

from .models import Asset

# 分隔符:中文 ，；：、。 + 英文 , ; | 制表符 空格(英文冒号绝不是分隔符,会拆坏 host:port/URL)
SPLIT_RE = re.compile(r"[,，;；：、。|\t\s]+")

IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
IP_PORT_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
HOST_PORT_RE = re.compile(
    r"^((?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}):(\d{1,5})$")
URL_RE = re.compile(r"^https?://", re.I)
EMAIL_RE = re.compile(r"^[\w.+-]+@([\w-]+\.)+[\w-]{2,}$")

# tldextract 只用自带快照,离线确定(PSL 含 gov.cn/com.cn 等全部国内公共后缀)
_extract = tldextract.TLDExtract(suffix_list_urls=())


def valid_ip(s: str) -> bool:
    m = IP_RE.match(s)
    return bool(m) and all(0 <= int(g) <= 255 for g in m.groups())


def valid_port(p: str | int) -> bool:
    try:
        return 1 <= int(p) <= 65535
    except (TypeError, ValueError):
        return False


def idna(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        return ""


def psl_root(host: str) -> str:
    """PSL 提取可注册根域:api.demo.gov.cn -> demo.gov.cn(不是 gov.cn)。"""
    r = _extract(host)
    return r.registered_domain.lower() if r and r.registered_domain else ""


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class IngestResult:
    def __init__(self) -> None:
        self.assets: list[Asset] = []      # 判型成功的标准资产(origin=user)
        self.residues: list[str] = []      # 代码判不出,待 LLM 兜底
        self.rejected: list[str] = []      # 彻底修不回


def split_line(line: str) -> list[str]:
    return [t for t in SPLIT_RE.split(line.strip()) if t]


def classify_token(token: str) -> Asset | None:
    """六种形态判定(§4.2)。判不出返回 None(进残渣)。"""
    t = token.strip().strip(".")
    if not t:
        return None
    if URL_RE.match(t):
        try:
            u = urlsplit(t)
        except ValueError:
            return None
        host = (u.hostname or "").lower().rstrip(".")
        if not host:
            return None
        if not is_ip(host):
            host = idna(host)
            if not host or not HOST_RE.match(host):
                return None
        try:
            port = u.port or (443 if u.scheme.lower() == "https" else 80)
        except ValueError:
            return None
        if not valid_port(port):
            return None
        path = u.path or "/"
        a = Asset(type="url", value=f"{host}:{port}", root=psl_root(host) if not is_ip(host) else "",
                  attrs={"scheme": u.scheme.lower(), "paths": [path]})
        return a
    m = IP_PORT_RE.match(t)
    if m and valid_ip(m.group(1)) and valid_port(m.group(2)):
        return Asset(type="ip:port", value=f"{m.group(1)}:{int(m.group(2))}",
                     attrs={"scheme": ""})
    if valid_ip(t):
        return Asset(type="ip", value=t)
    m = HOST_PORT_RE.match(t)
    if m:
        host = idna(m.group(1))
        if host and valid_port(m.group(4)):
            return Asset(type="domain:port", value=f"{host}:{int(m.group(4))}",
                         root=psl_root(host), attrs={"scheme": ""})
        return None
    if EMAIL_RE.match(t):
        t = t.split("@", 1)[1].lower()
    host = idna(t)
    if host and HOST_RE.match(host):
        return Asset(type="domain", value=host, root=psl_root(host))
    return None


class Derivation:
    """派生结果(§4.3):主机种子(触发 naabu)+ 根域(触发被动扩展)+ 用户端点。"""

    def __init__(self) -> None:
        self.seeds: dict[str, Asset] = {}          # host -> Asset(ip|domain, origin=user)
        self.roots: dict[str, str] = {}            # root -> root(已过守卫)
        self.user_endpoints: dict[str, Asset] = {}  # "host:port" -> endpoint Asset
        self.skipped_shared: list[str] = []        # 命中 shared_suffix 被守卫跳过的根


def load_shared_suffixes(root_dir: str) -> set[str]:
    import yaml

    path = os.path.join(root_dir, "data", "shared_suffix.yaml")
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return {s.lower() for s in data.get("suffixes", [])}


def derive(assets: list[Asset], cfg: dict, shared_suffixes: set[str]) -> Derivation:
    """贪心派生:端点回溯裸主机(->naabu),域名回溯根域(->被动扩展,受守卫)。"""
    d = Derivation()
    routing = cfg["routing"]
    scope_roots = {r.lower() for r in routing.get("scope_roots") or []}

    def add_root(host: str) -> None:
        if not routing.get("auto_expand_root", True):
            return
        root = psl_root(host)
        if not root:
            return
        if scope_roots and root not in scope_roots:
            return
        if routing.get("scope_skip_shared_suffix", True) and root in shared_suffixes:
            d.skipped_shared.append(root)
            return
        d.roots[root] = root

    for a in assets:
        if a.type == "ip":
            d.seeds.setdefault(a.value, Asset(type="ip", value=a.value, origin="user",
                                              source=a.source))
        elif a.type == "domain":
            d.seeds.setdefault(a.value, Asset(type="domain", value=a.value, root=a.root,
                                              origin="user", source=a.source))
            add_root(a.value)
        elif a.type in ("ip:port", "domain:port", "url"):
            host, port = a.value.rsplit(":", 1)
            ep = Asset(type="endpoint", value=f"{host}:{int(port)}", root=a.root,
                       origin="user", source=a.source, attrs=dict(a.attrs))
            key = ep.value
            if key in d.user_endpoints:  # 同端点合并路径
                old = d.user_endpoints[key]
                old.attrs["paths"] = sorted(set(old.attrs.get("paths", []))
                                            | set(ep.attrs.get("paths", [])))[:50]
                old.source = sorted(set(old.source) | set(ep.source))
            else:
                d.user_endpoints[key] = ep
            stype = "ip" if is_ip(host) else "domain"
            d.seeds.setdefault(host, Asset(type=stype, value=host, root=a.root,
                                           origin="user", source=a.source))
            if stype == "domain":
                add_root(host)
    return d


def ingest_lines(lines: list[str], cfg: dict, root_dir: str) -> tuple[IngestResult, Derivation]:
    """第一段清洗 + 派生。残渣由 pipeline 决定是否交 LLM 兜底。"""
    res = IngestResult()
    for line in lines:
        for token in split_line(line):
            a = classify_token(token)
            if a is not None:
                res.assets.append(a)
            else:
                res.residues.append(token)
    shared = load_shared_suffixes(root_dir)
    deriv = derive(res.assets, cfg, shared)
    return res, deriv


def merge_rescued(res: IngestResult, deriv: Derivation, rescued: list[Asset],
                  cfg: dict, root_dir: str) -> Derivation:
    """LLM 兜底救回的资产并入,重新派生。"""
    res.assets.extend(rescued)
    return derive(res.assets, cfg, load_shared_suffixes(root_dir))


def write_rejected(root_dir: str, tokens: list[str]) -> None:
    if not tokens:
        return
    path = os.path.join(root_dir, "logs", "input_rejected.jsonl")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    import time

    with open(path, "a", encoding="utf-8") as f:
        for t in tokens:
            f.write(json.dumps({"value": t, "ts": int(time.time())}, ensure_ascii=False) + "\n")
