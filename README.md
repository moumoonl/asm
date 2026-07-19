# ASM · 资产监控 LLM 流水线

周期性持续测绘 bug bounty 目标的 **http/https 服务资产**,发现**新增 / 变更 / 下架 / 复活 / 密钥泄露**,通过**钉钉**(或 CLI stdout)通知。

- 干净 Ubuntu **一键部署**,只需 **2 个 key**(LLM API key + 钉钉 webhook)
- 只关心 http/https 服务,不碰 ssh/rdp/mysql 等端口服务
- 插件化:新接一个开源工具 = 一个可执行文件 + 一个 yaml
- 状态用 sqlite,无外部服务依赖,无 Web UI,CLI 优先

设计文档(可直接指导二次开发):[`../asset-monitoring-design-v4.md`](../asset-monitoring-design-v4.md)(v4.3,含 §18 实测验证记录)。

---

## 目录

- [工作原理](#工作原理)
- [快速安装部署(Ubuntu)](#快速安装部署ubuntu)
- [快速开始](#快速开始)
- [输入格式(6 种形态)](#输入格式6-种形态)
- [CLI 命令](#cli-命令)
- [配置说明](#配置说明)
- [通知样例](#通知样例)
- [插件系统(扩展新工具)](#插件系统扩展新工具)
- [数据与状态](#数据与状态)
- [定时运行](#定时运行)
- [常见问题](#常见问题)
- [目录结构](#目录结构)

---

## 工作原理

```
targets.txt / asm run -t <目标>
   ▼
1 INGEST    输入清洗:代码判型 6 形态(中文标点/空格容错),LLM 兜底残渣
            -> 标准 Asset + 派生(裸主机种子 / PSL 根域)
2 COLLECT   根域 -> 被动源子域枚举:crtsh / gau / subfinder
3 NORMALIZE 端点规范指纹 host:port(剥路径);finding 同轮去重
4 DIFF      查 sqlite seen:新端点 -> 全量富化;已见 -> 等复探周期
5 ENRICH    种子 -> naabu top-1000 + 补探 80/443
            -> 候选端口必须经 httpx 确认是 http/https 才保留(只留 web)
            -> httpx 富化:状态码/标题/指纹/登录页/WAF/双签名
            -> resp_sig 折叠:同响应只留组代表进深扫
            -> 深扫:js_secrets(JS 密钥/内网引用)+ nuclei(仅 http 模板)
6 TRIAGE    LLM 归类增量(event 由管道判,category 由 LLM 判,正交)
7 NOTIFY    钉钉(webhook 空 -> stdout 兜底);写 seen/seeds
```

**持续监控**:每轮跑一遍。**httpx 每轮轻探**所有已见端点的 `change_sig`(status+title+tech,非侵入 GET 探活),发现变化先过**确认门**(再探 2 次,≥2/3 一致才确认,5xx/429/超时算抖动),确认后:
- **变更** → 重进富化/深扫管道 → 通知
- **下架**(连续确认不可访问)→ 标记 parked → 通知;之后复活再通知
- 事件冷却 2 轮防抖;种子每 K 轮 naabu 复扫

**两个 LLM 触点(仅此而已,确定性工作全在代码里)**:
- 触点 A:代码判不出的输入残渣 → 极窄 schema 救回
- 触点 B:富化+折叠后的增量 → 分类分级(泄露/登录页/高价值/噪声...)

## 快速安装部署(Ubuntu)

干净 **Ubuntu 22.04 / 24.04**,4 步上线。只需两个 key:LLM API key(建议)+ 钉钉 webhook(可选)。

### 1. 准备代理(国内必填,海外可跳过)

`github.com` / `api.github.com` / `crt.sh` / `web.archive.org` 等源国内直连不稳,先 export 代理。**装之前 export,会被写进 systemd timer,定时任务也走代理**:

```bash
export HTTPS_PROXY=http://127.0.0.1:7890
export HTTP_PROXY=http://127.0.0.1:7890
# 端口换成你本地代理实际端口(Clash/v2ray 等);确认能 curl 通 github.com 再继续
```

### 2. 一键安装

```bash
# 方式 A:克隆后跑(推荐,能 git pull 升级)
git clone https://github.com/moumoonl/asm.git && cd asm
bash install.sh

# 方式 B:一行 curl 直跑(不保留 .git,后续手动升级)
curl -fsSL https://raw.githubusercontent.com/moumoonl/asm/main/install.sh | bash
```

`install.sh` 做 6 件事:`apt` 依赖 → clone 到 `~/asm` → 下载预编译工具(subfinder/httpx/naabu/nuclei/katana/gau)到 `bin/` → **校验 nuclei 模板**(必须就绪,否则中止安装)→ 建 python venv → 填 key → 注册 systemd timer(按 `schedule.yaml`,默认每 6 小时)→ 创建 `asm` 命令。

### 3. 填两个 key

安装时**交互输入**(有终端时自动提示),或用环境变量**非交互**(适合自动化):

```bash
ASM_LLM_KEY=sk-xxx \
ASM_PUSH_WEBHOOK=https://oapi.dingtalk.com/robot/send?access_token=xxx \
bash install.sh
```

| key | 必填 | 说明 |
|---|---|---|
| LLM API key | 建议填 | OpenAI 兼容三件套(`base_url`/`model`/`api_key`),默认 DeepSeek。**留空则走规则直通模式**,不调用 LLM,管道照常跑 |
| 钉钉 webhook | 可选 | 留空则报告输出到 CLI stdout;钉钉加签 `secret` 可选 |

**事后改 key / 换模型**:直接编辑 `~/asm/config.yaml`(模板在 `config.example.yaml`)。改完不用重装,下次 `asm run` 即生效。

```yaml
# config.yaml 里要改的两处
llm:
  base_url: https://api.deepseek.com
  model: deepseek-v4-flash
  api_key: "sk-你的key"        # ← LLM key

push:
  channel: dingtalk
  webhook: "https://oapi.dingtalk.com/robot/send?access_token=xxx"  # ← 钉钉 webhook
  secret: ""                   # 钉钉加签(可选)
```

### 4. 验证

```bash
asm targets add example.com        # 加目标(或编辑 ~/asm/targets.txt)
asm run --dry                      # 首轮:建基线,写库不通知(强烈推荐)
asm status                         # 看资产数 / 上次运行统计
systemctl list-timers asm.timer    # 确认定时已注册
```

---

**macOS 本地跑(开发/测试)**:`brew install subfinder httpx naabu nuclei katana gau` + `python3 -m venv .venv && .venv/bin/pip install openai pydantic pyyaml tldextract "httpx[socks]"`,然后 `.venv/bin/python -m asm ...`。长任务建议 `caffeinate -i asm run` 防合盖休眠拖慢深扫。

## 快速开始

```bash
asm targets add example.com        # 加目标(或直接编辑 targets.txt)
asm run --dry                      # 首轮:建基线,写库不通知(强烈推荐)
asm run                            # 第二轮起:增量检测 + 通知
asm status                         # 看资产数/上次运行统计
```

## 输入格式(6 种形态)

`targets.txt` 一行一条,支持中文逗号/分号/句号/空格等脏数据,精准提取:

```
1.1.1.1                    # IP            -> 种子,naabu 全端口
1.1.1.1:8080               # IP:端口       -> 端点 + 派生种子
demo.com                   # 域名          -> 种子 + 根域(触发子域枚举)
api.demo.com:8080          # 域名:端口     -> 端点 + 派生
http://1.1.1.1/api         # URL(IP)      -> 端点(路径存 attrs.paths)
http://api.demo.com/v1     # URL(域名)    -> 端点 + 派生
https://www.demo.com:8889/api   # 显式端口 URL 同样支持
```

规则:email 取域名部分;URL 去 userinfo/query/fragment;无端口按 scheme 推断(http→80/https→443);IPv6 不支持;判不出的残渣先给 LLM 兜底,救不回的写 `logs/input_rejected.jsonl`,**永不静默丢弃**。共享托管后缀(github.io/aliyuncs.com 等)命中守卫,不扩展根域只测输入本身。

## CLI 命令

```bash
asm run [-t 目标 ...] [--dry]   # 跑一次流水线;-t 与 targets.txt 合并;--dry 建基线不通知
asm targets add <目标 ...>       # 加目标
asm targets remove <目标> [--purge]
                                # 默认只移出输入列表,历史资产继续监控(资产是累积的)
                                # --purge 连 seeds+seen+其下 finding 一起删,彻底停止
asm targets list                # 列出目标
asm lint-plugin <插件路径>       # 校验插件契约(喂样例输入,查退出码+JSONL 契约)
asm status                      # round/存活/parked/finding/种子数 + 上次运行统计
asm reload                      # 改 schedule.yaml 后的 timer 重载说明
```

## 配置说明

> 首次使用:`cp config.example.yaml config.yaml` 与 `cp targets.example.txt targets.txt`,再填入自己的 key 与目标。`config.yaml` / `targets.txt` 已被 `.gitignore` 忽略,不会进版本库。

`config.yaml` —— 只有两个 key 需要动,其余默认即可:

| 配置 | 默认 | 说明 |
|---|---|---|
| `llm.api_key` / `base_url` / `model` | DeepSeek | 留空 = 规则直通模式 |
| `push.webhook` / `secret` / `channel` | 空 / dingtalk | 空 -> stdout 兜底;`channel: none` 完全关闭 |
| `collectors.crtsh` | 开 | CT 证书子域;`retries`(默认3)/`timeout`(25s)/`backoff`(2s) 重试退避,crt.sh 502 抽风时稳化 |
| `collectors.*` | 全开 | gau / subfinder,只对根域跑 |
| `enrichers.naabu.ports` | top-1000 | connect 扫描免 root;`only_user_input` 只扫用户种子 |
| `enrichers.httpx.rate/timeout` | 50 / 10s | 探活+富化一体 |
| `enrichers.js_secrets.max_js` | 60 | 每端点抓 JS 上限 |
| `enrichers.nuclei` | `-as`, medium+ | 仅 http 模板,只跑折叠组代表 |
| `enrichers.ffuf_dirs` | **关** | 预留,字典自定后开 |
| `routing.scope_roots` | 空 | 范围白名单:只扩展这些根域 |
| `waf.deep_scan_representative_only` | true | 折叠组只深扫代表(省量防抖) |
| `revalidate.httpx_every_round` | true | httpx 变更检测每轮跑(非侵入);false 则仅每 K 轮 |
| `revalidate.every_rounds` | 4 | naabu 端口复扫每 K 轮;timer 6h × K=4 ≈ 每天 |
| `revalidate.confirmation_retries` | 2 | 确认门:再探次数,≥2/3 一致才确认 |
| `revalidate.cooldown_rounds` | 2 | 事件冷却防抖 |
| `state.retention_days` | 90 | 清理 90 天未见的死端点/旧 finding |
| `limits.max_assets_per_run` | 5000 | 单轮新端点截断(user 优先) |
| `output.enabled` / `output.dir` | 开 / `OUTPUT` | 每轮每工具详情落盘;`enabled: false` 关闭 |

插件配置通过 `ASM_PLUGIN_CONFIG` 环境变量(JSON)注入插件,**加配置项只改 yaml,不动框架代码**。

### 轮次详情(OUTPUT 目录)

每次 `asm run` 会在 `OUTPUT/round_NNN_<时间戳>/` 下落盘本轮**每个工具**的详细记录,方便逐轮复盘每个工具跑了什么、产出什么:

```
OUTPUT/round_003_20260719-221800/
  collectors_crtsh.txt      # 每次调用一段:输入摘要 + 原始 JSONL 输出 + stderr
  collectors_gau.txt
  collectors_subfinder.txt
  enrichers_naabu.txt
  enrichers_httpx.txt       # 含每轮复探的确认门投票探活
  enrichers_js_secrets.txt
  enrichers_nuclei.txt
  _summary.md               # 各工具调用次数/输入/产出汇总表 + 轮次结果
```

- 单工具 `.txt` 内每次调用一段:输入端点列表(关键 attrs)、插件原始 JSONL 输出(超 200 行截断)、stderr 尾部。
- `_summary.md` 汇总各工具调用次数/输入合计/产出合计,以及本轮新增/变更/下架/复活/finding 计数。
- `OUTPUT/` 已被 `.gitignore` 忽略,不会进版本库。

## 通知样例

```markdown
### 🛰 资产监控 · example.com · 07-18 17:22
🆕 新增 6 | ⚠️ 变更 2 | ⚠️ 下架 1 | 🆗 复活 0 | 🔐 泄露 1 | 📎 JS引用 2 | 🗜 折叠 5 | ⏭ 噪声 0

🔐 泄露(优先看)
1. [high] [aws-access-key] AKIA**** 见 http://a.example.com/static/app.js [规则 aws-access-key]

⚠️ 变更
1. api.example.com [[200] 管理平台-v2 nginx]

🆕 新资产
1. test.example.com [[200] ASM-Test-Home Python:3.12]

🗜 大量雷同(疑似 WAF/默认页)
- cdn.example.com 等 3 个端点同响应 [403] -> 已抽查代表 1 个
```

- 密钥**打码后**才入库/通知
- 折叠组只报代表 + 计数,防 WAF 默认页刷屏
- 钉钉长报告自动按 100 行分片;加签 secret 支持

## 插件系统(扩展新工具)

```
plugins/
├── collectors/   crtsh.py  gau.py  subfinder.py        # 被动:吃根域,吐 Asset
├── enrichers/    naabu.py  httpx.py  js_secrets.py  nuclei.py   # 主动:吃种子/存活端点,吐 Asset/Finding
└── notifiers/    dingtalk.py  stdout.py                # 吃报告 JSON,无输出
```

**新工具接入 = 一个可执行文件 + 一个同名 `<name>.manifest.yaml`**:

```yaml
name: mytool
phase: enricher            # collector | enricher | notifier
input: endpoint            # root=根域 | seed=主机种子 | endpoint=存活端点
accepts: [ip:port, domain:port, url]
emits: [asset, finding]
order: 45                  # naabu=10 httpx=20 js_secrets=40 nuclei=50(折叠由框架内部做,非插件)
timeout: 300
enabled: true
```

契约:stdin 收 JSONL,stdout 吐 JSONL(Asset 或 Finding,带 `schema_version: 1`),stderr 进 `logs/run.log`;崩溃/超时只影响自己,框架记日志继续。写完跑 `asm lint-plugin plugins/enrichers/mytool.py` 验证。

## 数据与状态

sqlite `state.db` 三张表(可删,删了全量重推):

- **seen** — 端点(host:port)+ finding 的生命周期:指纹/状态(live/parked)/last_sig/首末次见到/通知标记/冷却
- **seeds** — 主机种子调度:上次 naabu / 上次被动收集时间。**种子不进 seen、不做 httpx 复探、不被 diff 跳过**
- **meta** — round 计数 / 上次运行统计

安全设计:
- **单实例锁**:run 开始 flock `state.db.lock`,防 timer 与手动 run 并发写库/重复通知
- finding 指纹 = `sha256(type|value)`,密钥打码存储,同轮先自去重再查库,**不重复通知**
- 端点指纹 = `host:port`(小写、剥路径),同端点不管来源只富化一次、只推一次

## 定时运行

`schedule.yaml` 里是标准 cron 表达式(默认 `0 */6 * * *` 每 6 小时),install.sh 自动转成 systemd timer(`Persistent=true`,关机错过会补跑)。

```bash
systemctl list-timers asm.timer      # 看下次触发
journalctl -u asm.service -n 50      # 看运行日志
asm reload                           # 改了 schedule.yaml 后看重载说明
```

手动跑与 timer 互斥(flock),不用担心撞车。

## 常见问题

**Q: 首轮跑完钉钉收到几百条?**
A: 首轮用 `asm run --dry` 建基线(写库不通知),第二轮起只有增量。

**Q: 没有 LLM key 能用吗?**
A: 能。`llm.api_key` 留空走规则直通:按启发式归类(登录页/泄露/新资产),管道、去重、复探、通知全部照常。

**Q: naabu 扫出的 MySQL/SSH 端口会报吗?**
A: 不会。所有候选端口必须经 httpx 确认是 http/https 才进库,其它直接丢弃。

**Q: WAF/ CDN 域名怎么处理?**
A: 识别 behind_waf(响应头+指纹+CIDR 段),命中 WAF edge 的种子跳过 naabu;同响应端点按 resp_sig 折叠,只抽查代表,不刷屏。

**Q: 误报变更怎么办?**
A: 确认门要求再探 2 次 ≥2/3 一致;5xx/429/超时算瞬态抖动下轮复查;事件后冷却 2 轮。

**Q: 某个插件挂了会影响整体吗?**
A: 不会。插件子进程隔离,崩溃/超时只记日志,其他源和后续阶段照常。

**Q: httpx 首次运行卡住?**
A: 首次需下载 ~92MB 识别模型,慢就挂代理(`export HTTPS_PROXY=...`),下完即缓存。

**Q: 日志在哪?**
A: `logs/run.log`(运行)、`logs/input_rejected.jsonl`(清洗失败的输入)、`logs/llm_failures.jsonl`(LLM 异常)。

## 目录结构

```
asm/
├── install.sh              # Ubuntu 一键部署
├── config.yaml             # 配置(只两个 key 要填)
├── schedule.yaml           # cron 定时
├── targets.txt             # 目标,一行一条
├── asm/                    # 框架(python 包)
│   ├── cli.py              # CLI 入口
│   ├── pipeline.py         # 7 步流水线编排 + 复探确认门 + OUTPUT 落盘
│   ├── ingest.py           # 输入两段清洗 + 派生
│   ├── plugins.py          # 插件发现/manifest/运行/lint
│   ├── llm.py              # 两触点:输入兜底 + 结果归类
│   ├── state.py            # sqlite 三表 + flock
│   ├── notify.py           # 报告渲染 + 路由
│   ├── models.py           # Asset/Finding 契约 + 指纹 + 打码
│   └── config.py           # 配置加载/合并
├── plugins/
│   ├── collectors/         # crtsh / gau / subfinder
│   ├── enrichers/          # naabu / httpx / js_secrets / nuclei
│   └── notifiers/          # dingtalk / stdout
├── prompts/                # triage.txt / input_rescue.txt
├── data/                   # waf_ranges.yaml / shared_suffix.yaml
├── bin/                    # 预编译工具(install.sh 下载)
├── logs/                   # run.log / rejected / llm_failures
├── OUTPUT/                 # 每轮每工具详情(.gitignore 忽略)
└── state.db                # sqlite(可删,删了全量重推)
```

---

**已验证**:v4.3 设计 + P1 实现于 2026-07-19 完成真 DeepSeek + 19 真目标复测(INGEST 六形态单测、死主机路径、本地靶场全生命周期:新增→去重→变更→下架→复活,折叠/确认门/finding 去重均通过),记录见设计文档 §18。
