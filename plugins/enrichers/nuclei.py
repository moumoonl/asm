#!/usr/bin/env python3
"""nuclei enricher:-as 匹配模式,仅 http 模板,medium+(§7)。输出 Finding(type=nuclei)。"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

CFG = json.loads(os.environ.get("ASM_PLUGIN_CONFIG", "{}") or "{}")
ARGS = str(CFG.get("args", "-as"))
TAGS = str(CFG.get("tags", "exposure,misconfig,cve,detect"))
SEVERITY = str(CFG.get("severity", "medium,high,critical"))
RATE = str(CFG.get("rate", 30))
SCAN_TIMEOUT = int(CFG.get("scan_timeout", 3600))   # 0=不限,等 nuclei 跑完(manifest 外层兜底)


def find_bin(name: str) -> str:
    cand = os.path.join(os.environ.get("ASM_BIN_DIR", "."), name)
    if os.path.isfile(cand) and os.access(cand, os.X_OK):
        return cand
    return shutil.which(name) or name


def main() -> int:
    assets = [json.loads(l) for l in sys.stdin if l.strip()]
    if not assets:
        return 0
    targets = []
    for a in assets:
        scheme = (a.get("attrs") or {}).get("scheme") or "https"
        targets.append(f"{scheme}://{a['value']}")
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(targets))
        list_file = tf.name
    cmd = [find_bin("nuclei"), "-l", list_file] + ARGS.split() + [
        "-tags", TAGS, "-severity", SEVERITY, "-rate-limit", RATE,
        "-pt", "http", "-timeout", "10", "-jsonl", "-silent", "-no-color",
        "-stats", "-duc"]
    sub_to = SCAN_TIMEOUT if SCAN_TIMEOUT > 0 else None   # 0=不限,等 nuclei 跑完(manifest 外层兜底)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=sub_to)
    except subprocess.TimeoutExpired as e:
        # 超时:回收已流出的 JSONL 继续解析,并告知框架(不静默)
        print(f"[nuclei] 扫描超时({SCAN_TIMEOUT}s),回收部分输出", file=sys.stderr)
        out_lines = (e.stdout or "").splitlines() if isinstance(e.stdout, str) else []
        _emit(out_lines, assets)
        return 1
    finally:
        os.unlink(list_file)
    if p.returncode != 0:
        # nuclei 自身失败(如模板缺失/参数错误):报 stderr,不伪装成"0 finding"
        print(f"[nuclei] 退出码 {p.returncode}: {p.stderr[-500:]}", file=sys.stderr)
        return p.returncode
    _emit(p.stdout.splitlines(), assets)
    return 0


def _emit(lines: list, assets: list) -> None:
    root_of = {a["value"]: a.get("root", "") or a["value"].rsplit(":", 1)[0]
               for a in assets}
    for line in lines:
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        tid = r.get("template-id") or r.get("templateID") or ""
        info = r.get("info") or {}
        name = info.get("name", "")
        sev = (info.get("severity") or "medium").lower()
        matched = r.get("matched-at") or r.get("host") or ""
        host = matched.split("://", 1)[-1].split("/")[0]
        out = {"schema_version": 1, "kind": "finding", "type": "nuclei",
               "value": f"[{tid}] {name} @ {matched}",
               "root": root_of.get(host, ""),
               "source": ["nuclei"], "severity": sev,
               "evidence": f"模板 {tid},匹配 {matched}"
                           + (f",matcher {r['matcher-name']}" if r.get("matcher-name") else "")}
        print(json.dumps(out, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())
