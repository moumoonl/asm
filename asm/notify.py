"""通知:渲染报告 + 路由(钉钉有 webhook 走钉钉,否则落 stdout;stdout 永远兜底)(§13)。"""
from __future__ import annotations

import json
import time as _t

from .plugins import Plugin, run_plugin


def build_report(targets: list[str], triaged: list[dict], js_refs: list,
                 folded: list[dict], events_count: dict) -> dict:
    """triaged: 已合并 event/severity/kind 的归类结果(dict 列表)。"""
    return {"targets": targets, "triaged": triaged,
            "js_refs": [f.model_dump() if hasattr(f, "model_dump") else f for f in js_refs],
            "folded": folded, "counts": events_count,
            "noise": sum(1 for t in triaged if t.get("category") == "noise")}


def render_markdown(report: dict) -> str:
    c = report["counts"]
    targets = ", ".join(report["targets"][:3]) + ("..." if len(report["targets"]) > 3 else "")
    tri = [t for t in report["triaged"] if t.get("category") != "noise"]
    lines = [f"### 🛰 资产监控 · {targets} · {_t.strftime('%m-%d %H:%M')}"]
    lines.append(
        f"🆕 新增 {c.get('new', 0)} | ⚠️ 变更 {c.get('changed', 0)} | "
        f"⚠️ 下架 {c.get('takedown', 0)} | 🆗 复活 {c.get('revived', 0)} | "
        f"🔐 泄露 {sum(1 for t in tri if t['category'] == 'leaked_secret')} | "
        f"📎 JS引用 {len(report['js_refs'])} | 🗜 折叠 {sum(g['count'] for g in report['folded'])} | "
        f"⏭ 噪声 {report['noise']}")

    def sec(title: str, items: list[str]) -> None:
        if items:
            lines.append(f"\n{title}")
            lines.extend(f"{i}. {s}" for i, s in enumerate(items, 1))

    def fmt(t: dict) -> str:
        base = f"{t['value']}"
        if t.get("reason"):
            base += f" [{t['reason']}]"
        if t.get("suggest"):
            base += f" 建议:{t['suggest']}"
        return base

    sec("🔐 泄露(优先看)",
        [f"[{t.get('severity') or 'high'}] {fmt(t)}" for t in tri
         if t["category"] == "leaked_secret"])
    sec("⚠️ 变更", [fmt(t) for t in tri if t.get("event") == "changed"])
    sec("⚠️ 下架", [f"{t['value']} [{t.get('reason') or '确认无法访问'}]" for t in tri
                   if t.get("event") == "takedown"])
    sec("🆗 复活", [fmt(t) for t in tri if t.get("event") == "revived"])
    sec("🚪 登录/管理页", [fmt(t) for t in tri
                          if t["category"] == "login_panel" and t.get("event") == "new"])
    sec("⭐ 高价值", [fmt(t) for t in tri if t["category"] == "high_value"])
    sec("🆕 新资产", [fmt(t) for t in tri
                     if t["category"] in ("new_asset", "suspicious_api")
                     and t.get("event") == "new"][:50])
    if report["folded"]:
        lines.append("\n🗜 大量雷同(疑似 WAF/默认页)")
        for g in report["folded"][:10]:
            lines.append(f"- {g['rep']} 等 {g['count']} 个端点同响应 {g['info']} -> 已抽查代表 1 个")
    sec("📎 JS 引用(非公开域,直出)",
        [f"{f['value']}({str(f.get('evidence', ''))[:60]})" for f in report["js_refs"]][:30])
    return "\n".join(lines)


def dispatch(root: str, cfg: dict, plugins: list[Plugin], report: dict, log) -> None:
    text = render_markdown(report)
    webhook = cfg["push"].get("webhook", "")
    channel = cfg["push"].get("channel", "dingtalk")
    sent = False
    if webhook and channel != "none":
        ps = [p for p in plugins if p.phase == "notifiers" and p.name == channel]
        if ps:
            objs, err = run_plugin(root, cfg, ps[0], [json.dumps({
                "text": text, "push": dict(cfg["push"])}, ensure_ascii=False)],
                passthrough=True)
            if err:
                log(f"[notify] {channel} 发送失败: {err} -> 落 stdout")
            else:
                sent = True
                log(f"[notify] 已发送 {channel}")
    if not sent:
        ps = [p for p in plugins if p.phase == "notifiers" and p.name == "stdout"]
        if ps:
            run_plugin(root, cfg, ps[0], [json.dumps({"text": text}, ensure_ascii=False)],
                       passthrough=True)
        else:
            print(text)
        log("[notify] webhook 未配置/失败 -> 已输出 stdout")
