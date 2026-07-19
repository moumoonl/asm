"""统一数据契约:Asset / Finding + 规范指纹(设计文档 §2 §4.4)。

插件间只传这两种 JSONL。Finding 是叶子:不转 Asset、不派生、不回灌。
"""
from __future__ import annotations

import hashlib
import re
import time

from pydantic import BaseModel, Field

SCHEMA_VERSION = 1

# 内部归一后的端点统一用 endpoint;外部输入形态为前五种
ASSET_TYPES = {"ip", "ip:port", "domain", "domain:port", "url", "endpoint"}
FINDING_BUILTIN_TYPES = {"leaked_secret", "js_reference"}  # type 为开放字符串,插件可扩展
ORIGINS = {"user", "enumerated"}


class Asset(BaseModel):
    schema_version: int = SCHEMA_VERSION
    kind: str = "asset"
    type: str                       # ip | ip:port | domain | domain:port | url | endpoint
    value: str                      # 原始值或规范值(host / host:port / url)
    root: str = ""                  # 根域(PSL 提取,IP 则为空)
    origin: str = "user"            # user | enumerated
    source: list[str] = Field(default_factory=list)
    attrs: dict = Field(default_factory=dict)
    ts: int = Field(default_factory=lambda: int(time.time()))


class Finding(BaseModel):
    schema_version: int = SCHEMA_VERSION
    kind: str = "finding"
    type: str                       # leaked_secret | js_reference | nuclei | 自定义
    value: str                      # 展示值(密钥必须已打码)
    root: str = ""
    source: list[str] = Field(default_factory=list)
    severity: str = "info"          # info|low|medium|high|critical
    evidence: str = ""
    ts: int = Field(default_factory=lambda: int(time.time()))


def endpoint_fp(host: str, port: int) -> str:
    """端点规范指纹:host:port(小写,端口恒显式,路径剥离)。"""
    return hashlib.sha256(f"asset|endpoint|{host.lower()}:{int(port)}".encode()).hexdigest()


def finding_fp(ftype: str, value: str) -> str:
    return hashlib.sha256(f"finding|{ftype}|{value}".encode()).hexdigest()


_SECRET_RUN = re.compile(r"[A-Za-z0-9+/=_\-]{8,}")


def mask_secret(text: str, keep: int = 4) -> str:
    """把文本里疑似密钥的长串打码,只留前 keep 位。用于 Finding.value 落盘前处理。"""

    def _m(m: re.Match) -> str:
        s = m.group(0)
        return s[:keep] + "****" if len(s) > keep + 4 else s

    return _SECRET_RUN.sub(_m, text)


def parse_jsonl(text: str) -> list[dict]:
    """宽容解析 JSONL:跳过空行与坏行(插件崩溃隔离的一部分)。"""
    import json

    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                out.append(obj)
        except json.JSONDecodeError:
            continue
    return out


def to_asset(obj: dict) -> Asset | None:
    try:
        a = Asset(**obj)
        if a.kind != "asset":
            return None
        return a
    except Exception:
        return None


def to_finding(obj: dict) -> Finding | None:
    try:
        f = Finding(**obj)
        if f.kind != "finding":
            return None
        return f
    except Exception:
        return None
