"""插件系统:manifest 发现 + 子进程运行器(§3)。

插件 = 任意可执行文件 + 同名 <name>.manifest.yaml;stdin/stdout 传 JSONL;
配置经 ASM_PLUGIN_CONFIG 环境变量注入;崩了/超时只影响自己。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import yaml

from .models import parse_jsonl

PHASES = ("collectors", "enrichers", "notifiers")
PHASE_NORM = {"collector": "collectors", "collectors": "collectors",
              "enricher": "enrichers", "enrichers": "enrichers",
              "notifier": "notifiers", "notifiers": "notifiers"}


class Plugin:
    def __init__(self, path: str, manifest: dict):
        self.path = path
        self.dir = os.path.dirname(path)
        self.name = manifest.get("name") or os.path.basename(path).split(".")[0]
        self.phase = PHASE_NORM.get(manifest.get("phase", ""), manifest.get("phase", ""))
        self.input = manifest.get("input", "endpoint")
        self.accepts = manifest.get("accepts") or []
        self.emits = manifest.get("emits") or ["asset"]
        self.order = int(manifest.get("order", 100))
        self.timeout = int(manifest.get("timeout", 300))
        self.enabled = bool(manifest.get("enabled", True))
        self.manifest = manifest

    def __repr__(self) -> str:  # noqa: D105
        return f"<Plugin {self.phase}/{self.name} order={self.order}>"


def discover(root: str) -> list[Plugin]:
    """扫描 plugins/*/ 下所有 *.manifest.yaml,按 order 排序。"""
    plugins = []
    for phase in PHASES:
        pdir = os.path.join(root, "plugins", phase)
        if not os.path.isdir(pdir):
            continue
        for fn in sorted(os.listdir(pdir)):
            if not fn.endswith(".manifest.yaml"):
                continue
            mpath = os.path.join(pdir, fn)
            with open(mpath, "r", encoding="utf-8") as f:
                m = yaml.safe_load(f) or {}
            name = m.get("name") or fn[: -len(".manifest.yaml")]
            exe = None
            for ext in (".py", ".sh", ""):
                cand = os.path.join(pdir, name + ext)
                if os.path.isfile(cand) and os.access(cand, os.X_OK):
                    exe = cand
                    break
            if exe:
                plugins.append(Plugin(exe, m))
    plugins.sort(key=lambda p: p.order)
    return plugins


def cfg_for(cfg: dict, plugin: Plugin) -> dict:
    """config.yaml 同名 section 覆盖 manifest 默认值,合并后经 ASM_PLUGIN_CONFIG 注入。"""
    section = (cfg.get(plugin.phase) or {}).get(plugin.name) or {}
    merged = dict(plugin.manifest.get("defaults") or {})
    merged.update({k: v for k, v in section.items()})
    merged.setdefault("enabled", plugin.enabled)
    return merged


def is_enabled(cfg: dict, plugin: Plugin) -> bool:
    return bool(cfg_for(cfg, plugin).get("enabled", True))


def _record(plugin: Plugin, stdin_lines: list[str], stdout_raw: str, stderr: str,
            objs: list[dict], err: str, passthrough: bool) -> None:
    """落盘单次工具调用详情到 OUTPUT/<phase>_<name>.txt + _tally.jsonl。

    开关:环境变量 ASM_OUTPUT_DIR(仅 asm run 时由 pipeline 设置)。passthrough(通知器)不落盘。
    落盘失败绝不影响主流程(只 warn)。
    """
    if passthrough:
        return
    out_dir = os.environ.get("ASM_OUTPUT_DIR")
    if not out_dir:
        return
    try:
        os.makedirs(out_dir, exist_ok=True)
        ts = time.strftime("%H:%M:%S")
        # 输入摘要(value + 关键 attrs,前 50 个)
        in_lines: list[str] = []
        for ln in stdin_lines[:50]:
            try:
                o = json.loads(ln)
            except (json.JSONDecodeError, ValueError):
                in_lines.append(f"  - {ln[:120]}")
                continue
            val = o.get("value", "")
            attrs = o.get("attrs") or {}
            tag = ""
            if attrs.get("scheme"):
                tag += f"  [scheme={attrs['scheme']}]"
            if attrs.get("paths"):
                tag += f"  [paths={attrs['paths'][:3]}]"
            in_lines.append(f"  - {val}{tag}")
        if len(stdin_lines) > 50:
            in_lines.append(f"  ... +{len(stdin_lines) - 50} 个已省略")
        # 输出(插件 JSONL);超 200 行截断
        out_lines = (stdout_raw or "").splitlines()
        if objs and objs[0].get("kind") == "asset":
            out_kind = "asset"
        elif objs and objs[0].get("kind") == "finding":
            out_kind = "finding"
        else:
            out_kind = "-"
        shown = out_lines[:200]
        out_block = "\n".join(f"  {l}" for l in shown)
        if len(out_lines) > 200:
            out_block += f"\n  ... +{len(out_lines) - 200} 行已省略"
        stderr_tail = (stderr or "")[-500:].strip()
        # 调用序号:该工具在本轮的第几次调用(从 tally 已有同名行数推断,单线程无竞争)
        tally_path = os.path.join(out_dir, "_tally.jsonl")
        seq = 1
        if os.path.exists(tally_path):
            with open(tally_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        r = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if r.get("phase") == plugin.phase and r.get("name") == plugin.name:
                        seq += 1
        sect = [
            f"===== {plugin.phase}/{plugin.name} · 调用#{seq}  {ts} =====",
            f"输入: {len(stdin_lines)} 个",
            *in_lines,
            f"插件输出 ({len(out_lines)} 行 JSONL -> {len(objs)} {out_kind})"
            + (f"  [err: {err}]" if err else "") + ":",
            out_block if out_block else "  (无输出)",
            f"stderr: {stderr_tail if stderr_tail else '(空)'}",
            "-" * 60,
        ]
        with open(os.path.join(out_dir, f"{plugin.phase}_{plugin.name}.txt"), "a",
                  encoding="utf-8") as f:
            f.write("\n".join(sect) + "\n")
        with open(tally_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"phase": plugin.phase, "name": plugin.name, "ts": ts,
                                "input": len(stdin_lines), "output": len(objs),
                                "kind": out_kind, "err": err[:200]},
                               ensure_ascii=False) + "\n")
    except Exception as e:  # 落盘失败绝不影响主流程
        sys.stderr.write(f"[record] 落盘失败({plugin.name}): {e}\n")


def run_plugin(root: str, cfg: dict, plugin: Plugin, stdin_lines: list[str],
               timeout: int | None = None, passthrough: bool = False) -> tuple[list[dict], str]:
    """运行插件:喂 JSONL,收 stdout JSONL。崩溃/超时隔离,返回 (解析结果, stderr)。
    passthrough=True 时 stdout 直通终端(通知器用:报告直接显示,不解析)。"""
    env = dict(os.environ)
    env["ASM_PLUGIN_CONFIG"] = json.dumps(cfg_for(cfg, plugin), ensure_ascii=False)
    env["ASM_BIN_DIR"] = os.path.join(root, "bin")
    env["ASM_DATA_DIR"] = os.path.join(root, "data")
    env["ASM_ROOT"] = root
    if plugin.path.endswith(".py"):
        cmd = [sys.executable, plugin.path]
    else:
        cmd = [plugin.path]
    try:
        p = subprocess.run(
            cmd, input="\n".join(stdin_lines) + ("\n" if stdin_lines else ""),
            stdout=None if passthrough else subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True, timeout=timeout or plugin.timeout, env=env)
    except subprocess.TimeoutExpired as e:
        # 超时仍回收已流出的部分输出(插件应边跑边打印并 flush)
        partial = parse_jsonl(e.stdout or "") if not passthrough else []
        note = f"[plugin:{plugin.name}] 超时({timeout or plugin.timeout}s)"
        if partial:
            note += f",回收部分输出 {len(partial)} 行"
        _record(plugin, stdin_lines, e.stdout or "", e.stderr or "", partial, note, passthrough)
        return partial, note
    except OSError as e:
        note = f"[plugin:{plugin.name}] 启动失败: {e}"
        _record(plugin, stdin_lines, "", "", [], note, passthrough)
        return [], note
    if p.returncode != 0:
        note = f"[plugin:{plugin.name}] 退出码 {p.returncode}: {p.stderr[-500:]}"
        # 非零退出仍落盘已产出的部分输出(诊断用),但按原语义不返回给流水线
        partial = parse_jsonl(p.stdout or "") if not passthrough else []
        _record(plugin, stdin_lines, p.stdout or "", p.stderr or "", partial, note, passthrough)
        return [], note
    objs = parse_jsonl(p.stdout or "") if not passthrough else []
    _record(plugin, stdin_lines, p.stdout or "", p.stderr or "", objs, "", passthrough)
    return objs, p.stderr


def lint_plugin(root: str, cfg: dict, path: str) -> tuple[bool, str]:
    """asm lint-plugin:喂样例输入,校验退出码 0 且 stdout 每行符合契约。"""
    from .models import SCHEMA_VERSION

    mpath = None
    base = os.path.splitext(path)[0]
    for cand in (base + ".manifest.yaml",):
        if os.path.exists(cand):
            mpath = cand
    manifest = {}
    if mpath:
        with open(mpath, "r", encoding="utf-8") as f:
            manifest = yaml.safe_load(f) or {}
    plugin = Plugin(path, manifest)
    sample = {
        "root": [json.dumps({"schema_version": 1, "kind": "asset", "type": "domain",
                             "value": "example.com", "root": "example.com"})],
        "seed": [json.dumps({"schema_version": 1, "kind": "asset", "type": "ip",
                             "value": "127.0.0.1"})],
        "endpoint": [json.dumps({"schema_version": 1, "kind": "asset", "type": "endpoint",
                                 "value": "127.0.0.1:80"})],
    }.get(plugin.input, [])
    if plugin.phase == "notifier":
        sample = [json.dumps({"text": "lint test", "items": []})]
    objs, err = run_plugin(root, cfg, plugin, sample, timeout=min(plugin.timeout, 60))
    problems = []
    for o in objs:
        if o.get("schema_version") != SCHEMA_VERSION:
            problems.append(f"schema_version 缺失/错误: {str(o)[:120]}")
        if o.get("kind") not in ("asset", "finding"):
            problems.append(f"kind 非法: {str(o)[:120]}")
    if err and plugin.phase != "notifier" and not objs:
        problems.append(f"无输出且有 stderr: {err[:200]}")
    ok = not problems
    msg = "OK" if ok else "; ".join(problems)
    return ok, f"{plugin.phase or '?'}/{plugin.name}: {msg}({len(objs)} 行输出)"
