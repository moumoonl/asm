"""流水线编排:INGEST -> COLLECT -> NORMALIZE/DIFF -> ENRICH -> COLLAPSE -> TRIAGE -> NOTIFY(§1)。

端点进 seen 做生命周期;种子进 seeds 管调度;fold 提前到深扫前;确认门防误报级联。
"""
from __future__ import annotations

import json
import os
import time

from .ingest import classify_token, derive, ingest_lines, load_shared_suffixes, write_rejected
from .llm import LLM
from .models import Asset, Finding, endpoint_fp, finding_fp, to_asset, to_finding
from .notify import build_report, dispatch
from .plugins import discover, is_enabled, run_plugin
from .state import State


class Runner:
    def __init__(self, root: str, cfg: dict, dry: bool = False, verbose: bool = True):
        self.root = root
        self.cfg = cfg
        self.dry = dry
        self.log_lines: list[str] = []
        self.verbose = verbose
        self.state = State(root, cfg["state"]["path"])
        self.plugins = discover(root)
        self.llm = LLM(cfg, root, self.log)
        self.probed_this_run: set[str] = set()

    # ---------------- logging ----------------
    def log(self, msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        self.log_lines.append(line)
        if self.verbose:
            print(line, flush=True)
        path = os.path.join(self.root, "logs", "run.log")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    # ---------------- 插件调用辅助 ----------------
    def _plugins(self, phase: str, name: str | None = None):
        out = [p for p in self.plugins if p.phase == phase and is_enabled(self.cfg, p)]
        if name:
            out = [p for p in out if p.name == name]
        return out

    @staticmethod
    def _lines(assets: list[Asset]) -> list[str]:
        return [a.model_dump_json() for a in assets]

    def _run_assets(self, phase: str, name: str, assets: list[Asset]) -> tuple[list[Asset], list[Finding]]:
        ps = self._plugins(phase, name)
        if not ps or not assets:
            return [], []
        objs, err = run_plugin(self.root, self.cfg, ps[0], self._lines(assets))
        if err:
            self.log(err)
        return [a for o in objs if (a := to_asset(o))], [f for o in objs if (f := to_finding(o))]

    # ---------------- 主流程 ----------------
    def run(self, targets: list[str]) -> dict:
        st = self.state
        round_no = st.next_round()
        K = int(self.cfg["revalidate"]["every_rounds"])
        do_reval = (round_no % K == 0) and not self.dry
        self.log(f"=== run 开始 round={round_no} dry={self.dry} 复探本轮={'是' if do_reval else '否'} ===")

        # ---- 1 INGEST ----
        res, deriv = ingest_lines(targets, self.cfg, self.root)
        if res.residues:
            rescued: list[Asset] = []
            for item in self.llm.rescue(res.residues):
                a = classify_token(str(item.get("value", "")))
                if a is not None:
                    rescued.append(a)
                    self.log(f"[ingest] LLM 救回: {item.get('value')}")
            still = [t for t in res.residues
                     if not any(t in (r.value or "") for r in rescued)]
            write_rejected(self.root, still)
            if still:
                self.log(f"[ingest] 拒绝 {len(still)} 条(见 logs/input_rejected.jsonl)")
            if rescued:
                res.assets.extend(rescued)
                deriv = derive(res.assets, self.cfg, load_shared_suffixes(self.root))
        self.log(f"[ingest] 资产 {len(res.assets)} | 种子 {len(deriv.seeds)} | "
                 f"根域 {len(deriv.roots)} | 用户端点 {len(deriv.user_endpoints)}")
        for root_skipped in deriv.skipped_shared:
            self.log(f"[ingest] 根域 {root_skipped} 命中 shared_suffix,跳过扩展(只测输入本身)")

        # ---- 2 COLLECT(唯一根去重,被动) ----
        enumerated_subs: dict[str, Asset] = {}
        gau_endpoints: dict[str, Asset] = {}
        for root_domain in sorted(deriv.roots):
            root_asset = Asset(type="domain", value=root_domain, root=root_domain,
                               origin="user")
            for p in self._plugins("collectors"):
                objs, err = run_plugin(self.root, self.cfg, p, self._lines([root_asset]))
                if err:
                    self.log(err)
                n = 0
                for o in objs:
                    a = to_asset(o)
                    if not a:
                        continue
                    if a.type == "endpoint":
                        gau_endpoints.setdefault(a.value, a)
                    elif a.value.endswith(root_domain) and "*" not in a.value:
                        a.origin = "enumerated"
                        a.root = root_domain
                        enumerated_subs.setdefault(a.value, a)
                        n += 1
                self.log(f"[collect] {p.name} @ {root_domain} -> {n} 子域")
            st.seed_upsert(root_domain, root=root_domain, collect=True)

        # ---- 3 NORMALIZE:候选端点汇总 ----
        candidates: dict[str, Asset] = {}  # fp -> endpoint Asset

        def add_ep(host: str, port: int, origin: str, source: list[str],
                   root_: str = "", attrs: dict | None = None) -> None:
            fp = endpoint_fp(host, port)
            if fp in candidates:
                old = candidates[fp]
                old.source = sorted(set(old.source) | set(source))
                pa = old.attrs.get("paths", [])
                old.attrs["paths"] = sorted(set(pa) | set((attrs or {}).get("paths", [])))[:50]
                return
            candidates[fp] = Asset(type="endpoint", value=f"{host}:{port}", root=root_,
                                   origin=origin, source=list(source), attrs=attrs or {})

        for ep in deriv.user_endpoints.values():
            host, port = ep.value.rsplit(":", 1)
            add_ep(host, int(port), "user", ep.source, ep.root, dict(ep.attrs))
        for sub in enumerated_subs.values():
            add_ep(sub.value, 80, "enumerated", sub.source, sub.root)
            add_ep(sub.value, 443, "enumerated", sub.source, sub.root)
        for ep in gau_endpoints.values():
            host, port = ep.value.rsplit(":", 1)
            add_ep(host, int(port), "enumerated", ep.source, ep.root, dict(ep.attrs))

        # ---- 5a ENRICH:种子 -> naabu + 补探 80/443 ----
        naabu_due: list[Asset] = []
        rescan = bool(self.cfg["revalidate"].get("naabu_rescan_user_hosts", True))
        for seed in deriv.seeds.values():
            old = st.seed_get(seed.value)
            if old is None or (do_reval and rescan):
                naabu_due.append(seed)
            for port in (80, 443):  # 种子始终补探 80/443(WAF 跳 naabu 时兜底)
                add_ep(seed.value, port, "user", seed.source, seed.root)
        if naabu_due:
            self.log(f"[enrich] naabu 扫 {len(naabu_due)} 个种子: "
                     f"{', '.join(s.value for s in naabu_due)}")
            eps, _ = self._run_assets("enrichers", "naabu", naabu_due)
            for ep in eps:
                try:
                        host, port = ep.value.rsplit(":", 1)
                except ValueError:
                    continue
                add_ep(host, int(port), "enumerated", ep.source or ["naabu"], ep.root,
                       dict(ep.attrs))
            for seed in naabu_due:
                st.seed_upsert(seed.value, root=seed.root, naabu=True)
        else:
            for seed in deriv.seeds.values():
                st.seed_upsert(seed.value, root=seed.root)
        self.log(f"[enrich] 候选端点合计 {len(candidates)}")

        # ---- 4 DIFF:新端点 vs 已见 ----
        new_eps: list[Asset] = []
        for fp, a in candidates.items():
            if st.seen_get(fp):
                st.seen_touch(fp)
            else:
                new_eps.append(a)
        # 截断:origin=user 优先
        limit = int(self.cfg["limits"]["max_assets_per_run"])
        if len(new_eps) > limit:
            new_eps.sort(key=lambda a: (a.origin != "user", a.value))
            dropped = len(new_eps) - limit
            new_eps = new_eps[:limit]
            self.log(f"[diff] 新端点超限,截断 {dropped}(优先保留 user)")
        self.log(f"[diff] 新端点 {len(new_eps)} / 候选 {len(candidates)}")

        # ---- 5b ENRICH:httpx 探活+富化新端点 ----
        live_new = self._probe(new_eps)
        parked_new = 0
        for fp, a in live_new.items():
            st.seen_upsert(fp, "endpoint", "endpoint", a.value, a.root, "live",
                           last_sig=a.attrs.get("change_sig", ""))
        for a in new_eps:
            fp = endpoint_fp(*a.value.rsplit(":", 1))
            if fp not in live_new:
                st.seen_upsert(fp, "endpoint", "endpoint", a.value, a.root, "parked")
                parked_new += 1
        self.log(f"[enrich] httpx:活 {len(live_new)} 死 {parked_new}(parked 不通知)")

        # ---- 复探(每 K 轮):已见端点变化检测 ----
        changed: list[Asset] = []
        takedown: list[Asset] = []
        revived: list[Asset] = []
        if do_reval:
            changed, takedown, revived = self._revalidate(round_no)
            self.log(f"[revalidate] 变更 {len(changed)} 下架 {len(takedown)} 复活 {len(revived)}")

        # ---- 6 COLLAPSE:resp_sig 折叠(深扫前) ----
        live_all = list(live_new.values()) + changed + revived
        events = {id(a): "new" for a in live_new.values()}
        events.update({id(a): "changed" for a in changed})
        events.update({id(a): "revived" for a in revived})
        groups: dict[str, list[Asset]] = {}
        for a in live_all:
            groups.setdefault(a.attrs.get("resp_sig") or f"__solo__{a.value}", []).append(a)
        reps: list[Asset] = []
        folded: list[dict] = []
        for sig, members in groups.items():
            reps.append(members[0])
            if len(members) >= 2:
                rep = members[0]
                folded.append({"rep": rep.value, "count": len(members),
                               "info": f"[{rep.attrs.get('status')}] {rep.attrs.get('title', '')} "
                                       f"{rep.attrs.get('behind_waf') or ''}".strip()})
        if folded:
            self.log(f"[collapse] {sum(g['count'] for g in folded)} 个端点折成 "
                     f"{len(folded)} 组")

        # ---- 深扫:js_secrets + nuclei(只跑代表) ----
        if not self.cfg["waf"].get("deep_scan_representative_only", True):
            reps = live_all
        findings: list[Finding] = []
        if reps:
            for name in ("js_secrets", "nuclei"):
                _, fs = self._run_assets("enrichers", name, reps)
                findings.extend(fs)
                self.log(f"[deepscan] {name} -> {len(fs)} finding")

        # finding 同轮去重 + seen 去重
        new_findings: list[Finding] = []
        seen_fps: set[str] = set()
        for f in findings:
            fp = finding_fp(f.type, f.value)
            if fp in seen_fps:
                continue
            seen_fps.add(fp)
            if st.seen_get(fp):
                continue
            st.seen_upsert(fp, "finding", f.type, f.value, f.root, "-")
            new_findings.append(f)

        # ---- 7 TRIAGE ----
        items = []
        rep_ids = {id(a) for a in reps}
        for a in live_all:
            ev = events.get(id(a), "new")
            if self.cfg["waf"].get("collapse_identical_responses", True) and id(a) not in rep_ids:
                continue  # 折叠掉的只进计数不进 LLM
            items.append({"value": a.value, "event": ev, "kind": "asset", "type": "endpoint",
                          "attrs": {k: a.attrs.get(k) for k in
                                    ("status", "title", "tech", "behind_waf", "is_login_page",
                                     "scheme")}})
        for a in takedown:
            items.append({"value": a.value, "event": "takedown", "kind": "asset",
                          "type": "endpoint", "attrs": a.attrs})
        direct_refs = [f for f in new_findings if f.type == "js_reference"]
        for f in new_findings:
            if f.type == "js_reference":
                continue  # 引用类直出,不过 LLM
            items.append({"value": f.value, "event": "new", "kind": "finding",
                          "type": f.type, "severity": f.severity, "evidence": f.evidence})
        triaged_objs = self.llm.triage(items) if not self.dry else []
        meta = {it["value"]: it for it in items}
        triaged: list[dict] = []
        for t in triaged_objs:
            d = t.model_dump()
            src = meta.get(t.value, {})
            d["event"] = src.get("event", "new")
            d["severity"] = src.get("severity", "")
            d["kind"] = src.get("kind", "asset")
            triaged.append(d)

        # ---- 8 NOTIFY ----
        report = build_report(targets, triaged, direct_refs, folded, events_count={
            "new": len(live_new), "changed": len(changed), "takedown": len(takedown),
            "revived": len(revived), "findings": len(new_findings)})
        if self.dry:
            self.log("[dry] 建基线模式:已写 seen/seeds,跳过 LLM 与通知")
        elif not triaged and not direct_refs:
            # 本轮无事件(无新增/变更/下架/复活/finding):不打扰,只记日志(§8 noise 不通知)
            self.log("[notify] 本轮无变化,跳过通知")
        else:
            dispatch(self.root, self.cfg, self.plugins, report, self.log)
            for fp, a in [(endpoint_fp(*x.value.rsplit(":", 1)), x) for x in live_all]:
                st.db.execute("UPDATE seen SET notified=1 WHERE fp=?", (fp,))
            st.db.commit()

        # ---- 收尾 ----
        purged = st.purge(int(self.cfg["state"]["retention_days"]))
        if purged:
            self.log(f"[state] retention 清理 {purged} 条")
        st.meta_set("last_run", json.dumps({
            "ts": int(time.time()), "round": round_no, "new": len(live_new),
            "changed": len(changed), "takedown": len(takedown), "revived": len(revived),
            "findings": len(new_findings)}, ensure_ascii=False))
        self.log("=== run 结束 ===")
        return report

    # ---------------- httpx 探测(活->fp:Asset 富化) ----------------
    def _probe(self, assets: list[Asset]) -> dict[str, Asset]:
        if not assets:
            return {}
        out, _ = self._run_assets("enrichers", "httpx", assets)
        res = {}
        for a in out:
            try:
                fp = endpoint_fp(*a.value.rsplit(":", 1))
            except ValueError:
                continue
            self.probed_this_run.add(fp)
            res[fp] = a
        return res

    # ---------------- 复探 + 确认门(§9.4-9.6) ----------------
    def _revalidate(self, round_no: int) -> tuple[list[Asset], list[Asset], list[Asset]]:
        st = self.state
        rows = [r for r in st.seen_endpoints(("live", "parked"))
                if r["fp"] not in self.probed_this_run]
        if not rows:
            return [], [], []
        assets = [Asset(type="endpoint", value=r["value"], root=r["root"] or "")
                  for r in rows]
        cur = self._probe(assets)
        retries = int(self.cfg["revalidate"]["confirmation_retries"])
        cooldown_rounds = int(self.cfg["revalidate"]["cooldown_rounds"])
        changed, takedown, revived = [], [], []

        def confirm(a: Asset) -> list[Asset | None]:
            """确认门:再探 retries 次,返回每次结果(活 Asset / 死 None)。"""
            outs = []
            for _ in range(retries):
                time.sleep(2)
                one = self._probe([a])
                fp = endpoint_fp(*a.value.rsplit(":", 1))
                outs.append(one.get(fp))
            return outs

        for r, a in zip(rows, assets):
            fp, state, last_sig = r["fp"], r["state"], r["last_sig"] or ""
            now = cur.get(fp)
            in_cooldown = round_no < int(r["cooldown_until"] or 0)
            if state == "parked":
                if now is None:
                    st.seen_touch(fp, probed=True)
                    continue
                votes = [x for x in confirm(a) if x is not None]
                if len(votes) >= max(1, retries - 1) and votes[0].attrs.get("change_sig"):
                    sig = votes[0].attrs["change_sig"]
                    st.seen_upsert(fp, "endpoint", "endpoint", a.value, a.root, "live",
                                   last_sig=sig, notified=0,
                                   cooldown_until=round_no + cooldown_rounds)
                    revived.append(now)
                else:
                    st.seen_touch(fp, probed=True)
                continue
            # live
            if now is None:
                votes = confirm(a)
                if sum(x is None for x in votes) >= max(1, retries - 1):
                    st.seen_upsert(fp, "endpoint", "endpoint", a.value, a.root, "parked",
                                   cooldown_until=round_no + cooldown_rounds)
                    takedown.append(Asset(type="endpoint", value=a.value, root=a.root,
                                          attrs={"event_note": "确认下架(连续探测失败)"}))
                else:
                    st.seen_touch(fp, probed=True)  # 抖动,不算下架
                continue
            status = int(now.attrs.get("status") or 0)
            if status == 429 or 500 <= status < 600:
                st.seen_touch(fp, probed=True)  # 瞬态,下轮复查
                continue
            new_sig = now.attrs.get("change_sig", "")
            if new_sig == last_sig:
                st.seen_touch(fp, probed=True)
                continue
            votes = [x for x in confirm(a) if x is not None]
            agree = sum(x.attrs.get("change_sig") == new_sig for x in votes)
            if votes and agree >= max(1, retries - 1):
                st.seen_upsert(fp, "endpoint", "endpoint", a.value, a.root, "live",
                               last_sig=new_sig, notified=0,
                               cooldown_until=round_no + cooldown_rounds)
                if not in_cooldown:
                    changed.append(now)
            else:
                self.log(f"[revalidate] {a.value} sig 抖动,跳过本轮")
                st.seen_touch(fp, probed=True)
        return changed, takedown, revived
