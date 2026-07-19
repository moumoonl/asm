"""CLI:asm run / targets / lint-plugin / status / reload(§11)。"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    from .config import load_config
    return load_config(ROOT)


def _read_targets(cli_targets: list[str]) -> list[str]:
    lines = list(cli_targets)
    path = os.path.join(ROOT, "targets.txt")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            lines.extend(l for l in f.read().splitlines() if l.strip()
                         and not l.strip().startswith("#"))
    return lines


def cmd_run(args) -> int:
    from .pipeline import Runner
    from .state import StateLock

    targets = _read_targets(args.target or [])
    if not targets:
        print("[asm] 无目标:`asm run -t <目标>` 或写入 targets.txt", file=sys.stderr)
        return 2
    cfg = _load()
    with StateLock(ROOT):
        runner = Runner(ROOT, cfg, dry=args.dry)
        runner.run(targets)
        runner.state.close()
    return 0


def cmd_targets(args) -> int:
    path = os.path.join(ROOT, "targets.txt")
    if args.action == "add":
        existing = set()
        if os.path.exists(path):
            existing = {l.strip() for l in open(path, encoding="utf-8") if l.strip()}
        with open(path, "a", encoding="utf-8") as f:
            for t in args.values:
                if t.strip() and t.strip() not in existing:
                    f.write(t.strip() + "\n")
                    print(f"[asm] + {t.strip()}")
        return 0
    if args.action == "remove":
        if not os.path.exists(path):
            return 0
        lines = [l for l in open(path, encoding="utf-8")
                 if l.strip() and l.strip() not in set(args.values)]
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        print(f"[asm] 已从 targets.txt 移除 {args.values}")
        if args.purge:
            from .state import State
            st = State(ROOT, _load()["state"]["path"])
            for t in args.values:
                n = st.purge_target(t.strip())
                print(f"[asm] purge {t}: 清理 {n} 行(seeds+seen)")
            st.close()
        else:
            print("[asm] 历史资产继续监控;要彻底停止加 --purge")
        return 0
    # list
    if os.path.exists(path):
        print(open(path, encoding="utf-8").read(), end="")
    return 0


def cmd_lint(args) -> int:
    from .plugins import lint_plugin
    ok, msg = lint_plugin(ROOT, _load(), args.path)
    print(msg)
    return 0 if ok else 1


def cmd_status(args) -> int:
    from .state import State
    st = State(ROOT, _load()["state"]["path"])
    last = st.meta_get("last_run", "")
    n_live = st.db.execute("SELECT COUNT(*) c FROM seen WHERE kind='endpoint' AND state='live'").fetchone()["c"]
    n_parked = st.db.execute("SELECT COUNT(*) c FROM seen WHERE kind='endpoint' AND state='parked'").fetchone()["c"]
    n_finding = st.db.execute("SELECT COUNT(*) c FROM seen WHERE kind='finding'").fetchone()["c"]
    n_seed = st.db.execute("SELECT COUNT(*) c FROM seeds").fetchone()["c"]
    print(f"round={st.meta_get('round','0')} live={n_live} parked={n_parked} "
          f"findings={n_finding} seeds={n_seed}")
    if last:
        d = json.loads(last)
        print(f"上次运行: {time.strftime('%m-%d %H:%M', time.localtime(d['ts']))} "
          f"新增={d['new']} 变更={d['changed']} 下架={d['takedown']} "
          f"复活={d['revived']} findings={d['findings']}")
    st.close()
    return 0


def cmd_reload(args) -> int:
    timer = os.path.join(ROOT, "asm.timer")
    print("[asm] 定时由 systemd 管理。改了 schedule.yaml 后,在 Ubuntu 上执行:\n"
          "  sudo systemd-analyze calendar \"$(grep ^run schedule.yaml | cut -d'\"' -f2)\" 验证表达式\n"
          "  sudo systemctl restart asm.timer")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="asm", description="资产监控 LLM 流水线")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="跑一次流水线")
    p.add_argument("-t", "--target", action="append", help="目标(可多次)")
    p.add_argument("--dry", action="store_true", help="建基线:写 seen 但不调 LLM 不通知")
    p.set_defaults(fn=cmd_run)

    p = sub.add_parser("targets", help="管理 targets.txt")
    p.add_argument("action", choices=["add", "remove", "list"])
    p.add_argument("values", nargs="*")
    p.add_argument("--purge", action="store_true", help="remove 时清理其 seeds+seen")
    p.set_defaults(fn=cmd_targets)

    p = sub.add_parser("lint-plugin", help="校验插件契约")
    p.add_argument("path")
    p.set_defaults(fn=cmd_lint)

    p = sub.add_parser("status", help="运行状态")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("reload", help="重载定时说明")
    p.set_defaults(fn=cmd_reload)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
