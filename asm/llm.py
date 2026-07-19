"""LLM 交互契约(§8):两触点 + 五道保险。api_key 为空 -> 规则直通模式(降级可测)。"""
from __future__ import annotations

import json
import os

from pydantic import BaseModel, ValidationError

PROMPT_DIR = "prompts"


class RescueItem(BaseModel):
    value: str
    type: str
    note: str = ""


class TriageItem(BaseModel):
    value: str
    category: str = "new_asset"
    priority: int = 3
    reason: str = ""
    suggest: str = ""


CATEGORIES = {"new_asset", "login_panel", "suspicious_api", "leaked_secret",
              "js_reference", "high_value", "noise"}


def _read_prompt(root: str, name: str) -> str:
    path = os.path.join(root, PROMPT_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class LLM:
    """OpenAI 兼容三件套;JSON mode + temperature=0 + pydantic + repair 一轮 + 批次隔离。"""

    def __init__(self, cfg: dict, root: str, log):
        self.cfg = cfg["llm"]
        self.root = root
        self.log = log
        self.enabled = bool(self.cfg.get("api_key"))
        self.client = None
        if self.enabled:
            from openai import OpenAI

            self.client = OpenAI(base_url=self.cfg["base_url"], api_key=self.cfg["api_key"],
                                 timeout=120)
        else:
            log("[llm] api_key 为空 -> 规则直通模式(不调用 LLM,按启发式归类)")

    # ---------- 底层调用:JSON mode + repair + retry ----------
    def _chat_json(self, system: str, user: str) -> dict | None:
        if not self.enabled:
            return None
        messages = [{"role": "system", "content": system},
                    {"role": "user", "content": user}]
        attempts = 1 + int(self.cfg.get("retry", 1)) + 1  # 首次 + repair一轮 + retry
        last_err = ""
        for i in range(attempts):
            try:
                r = self.client.chat.completions.create(
                    model=self.cfg["model"], messages=messages, temperature=0,
                    response_format={"type": "json_object"})
                content = r.choices[0].message.content or ""
                return json.loads(content)
            except json.JSONDecodeError as e:  # repair:把错误塞回去让它修
                last_err = f"JSON 解析失败: {e}"
                messages.append({"role": "user",
                                 "content": f"上次输出不是合法 JSON({e}),请只输出修正后的 JSON。"})
            except Exception as e:  # API 错误,重试
                last_err = str(e)
                self.log(f"[llm] 调用失败(第{i + 1}次): {e}")
        self._fail("llm_call", last_err)
        return None

    def _fail(self, stage: str, detail: str) -> None:
        path = os.path.join(self.root, "logs", "llm_failures.jsonl")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        import time

        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"stage": stage, "detail": detail[:500],
                                "ts": int(time.time())}, ensure_ascii=False) + "\n")

    # ---------- 触点 A:输入兜底 ----------
    def rescue(self, residues: list[str]) -> list[dict]:
        if not residues or not self.enabled:
            return []
        system = _read_prompt(self.root, "input_rescue.txt")
        out: list[dict] = []
        batch = int(self.cfg.get("batch_size", 200))
        for i in range(0, len(residues), batch):  # 批次隔离:坏批丢弃不影响好批
            chunk = residues[i:i + batch]
            data = self._chat_json(system, "\n".join(chunk))
            if not data:
                self._fail("input_rescue", f"批次 {i // batch} 失败,{len(chunk)} 行丢弃")
                continue
            for raw in data.get("items", []):
                try:
                    item = RescueItem(**raw)
                    out.append(item.model_dump())
                except ValidationError:
                    continue
        return out

    # ---------- 触点 B:TRIAGE 归类 ----------
    def triage(self, items: list[dict]) -> list[TriageItem]:
        """items: [{value, event, kind, type, attrs/evidence...}];输出带 category/priority。"""
        if not items:
            return []
        if not self.enabled:
            return [self._passthrough(it) for it in items]
        system = _read_prompt(self.root, "triage.txt")
        results: dict[str, TriageItem] = {}
        batch = int(self.cfg.get("batch_size", 200))
        for i in range(0, len(items), batch):
            chunk = items[i:i + batch]
            data = self._chat_json(system, json.dumps({"items": chunk}, ensure_ascii=False))
            if not data:
                self._fail("triage", f"批次 {i // batch} 失败,{len(chunk)} 条按兜底归类")
                continue
            for raw in data.get("items", []):
                try:
                    t = TriageItem(**raw)
                    if t.category not in CATEGORIES:
                        t.category = "new_asset"
                    results[t.value] = t
                except ValidationError:
                    continue
        # 缺漏兜底:new_asset/priority=3,不丢弃
        return [results.get(it["value"], self._passthrough(it)) for it in items]

    @staticmethod
    def _passthrough(it: dict) -> TriageItem:
        """无 key 或 LLM 缺漏时的启发式归类。"""
        if it.get("kind") == "finding":
            cat = it.get("type") if it.get("type") in CATEGORIES else (
                "leaked_secret" if it.get("type") == "leaked_secret" else
                "js_reference" if it.get("type") == "js_reference" else "high_value")
            sev = it.get("severity", "info")
            pri = {"critical": 1, "high": 1, "medium": 2}.get(sev, 3)
            return TriageItem(value=it["value"], category=cat, priority=pri,
                              reason=it.get("evidence", "")[:120])
        attrs = it.get("attrs", {})
        if attrs.get("is_login_page"):
            return TriageItem(value=it["value"], category="login_panel", priority=2,
                              reason=f"登录页特征 [{attrs.get('status')}] {attrs.get('title', '')}")
        return TriageItem(value=it["value"], category="new_asset", priority=3,
                          reason=f"[{attrs.get('status')}] {attrs.get('title', '')} "
                                 f"{'/'.join(attrs.get('tech', []))}")
