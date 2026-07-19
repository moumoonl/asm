"""配置加载:config.yaml + 默认值深合并。改配置不动代码(需求 2)。"""
from __future__ import annotations

import os

import yaml

DEFAULTS: dict = {
    "llm": {
        "base_url": "https://api.deepseek.com",
        "model": "deepseek-v4-flash",
        "api_key": "",
        "batch_size": 200,
        "retry": 1,
    },
    "push": {"channel": "dingtalk", "webhook": "", "secret": ""},
    "collectors": {
        "crtsh": {"enabled": True},
        "gau": {"enabled": True},
        "subfinder": {"enabled": True},
    },
    "enrichers": {
        "httpx": {"enabled": True, "rate": 50, "timeout": 10},
        "naabu": {"enabled": True, "ports": "top-1000", "only_user_input": True,
                  "skip_waf_edge": True},
        "js_secrets": {"enabled": True, "max_js": 200, "no_derive": True},
        "nuclei": {"enabled": True, "args": "-as", "tags": "exposure,misconfig,cve,detect",
                   "severity": "medium,high,critical", "rate": 30, "http_only": True},
        "ffuf_dirs": {"enabled": False, "wordlist": ""},
    },
    "notifiers": {
        "dingtalk": {"enabled": True},
        "stdout": {"enabled": True},
    },
    "routing": {
        "naabu_on_user_input_only": True,
        "auto_expand_root": True,
        "scope_roots": [],
        "scope_skip_shared_suffix": True,
        "public_suffix_list": True,
    },
    "waf": {
        "detect": True,
        "collapse_identical_responses": True,
        "resp_body_bytes": 8192,
        "normalize_body": True,
        "deep_scan_representative_only": True,
    },
    "revalidate": {
        "every_rounds": 4,
        "change_sig": "status+title+tech",
        "confirmation_retries": 2,
        "cooldown_rounds": 2,
        "naabu_rescan_user_hosts": True,
    },
    "state": {"path": "state.db", "retention_days": 90},
    "limits": {"collector_timeout": 300, "max_assets_per_run": 5000},
}


def _merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(root: str) -> dict:
    path = os.path.join(root, "config.yaml")
    user = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
    cfg = _merge(DEFAULTS, user)
    # 环境变量兜底(非交互安装)
    if not cfg["llm"].get("api_key"):
        cfg["llm"]["api_key"] = os.environ.get("ASM_LLM_KEY", "")
    if not cfg["push"].get("webhook"):
        cfg["push"]["webhook"] = os.environ.get("ASM_PUSH_WEBHOOK", "")
    return cfg
