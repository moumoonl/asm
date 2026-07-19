#!/usr/bin/env bash
# 资产监控 LLM 流水线 · 一键部署(干净 Ubuntu)
# 用法: curl -fsSL <raw>/install.sh | bash   或   bash install.sh
# 只需要两个 key:LLM API key(必填)+ 钉钉 webhook(可选);代理:先 export HTTPS_PROXY=...
set -euo pipefail

INSTALL_DIR="${ASM_DIR:-$HOME/asm}"
REPO_URL="${ASM_REPO:-https://github.com/moumoonl/asm}"
BIN_DIR="$INSTALL_DIR/bin"

echo "==> [1/6] apt 依赖"
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-venv curl unzip jq ca-certificates

echo "==> [2/6] 拉代码"
if [ ! -d "$INSTALL_DIR/asm" ]; then
  mkdir -p "$INSTALL_DIR"
  if command -v git >/dev/null 2>&1; then
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" 2>/dev/null || true
  fi
  # 无 git 或 clone 失败时,假设当前目录就是代码目录,拷贝过去
  if [ ! -d "$INSTALL_DIR/asm" ]; then
    SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cp -r "$SRC"/{asm,plugins,prompts,data,config.example.yaml,schedule.yaml,targets.example.txt} "$INSTALL_DIR/" 2>/dev/null || true
  fi
fi
cd "$INSTALL_DIR"

echo "==> [3/6] 下载预编译工具到 bin/"
mkdir -p "$BIN_DIR"
ARCH=$(uname -m); [ "$ARCH" = "x86_64" ] && ARCH="amd64" || ARCH="arm64"
dl() {  # dl <name> <github_repo> <asset_pattern>
  local name="$1" repo="$2" pat="$3"
  if [ -x "$BIN_DIR/$name" ]; then echo "  $name 已存在,跳过"; return; fi
  local url
  url=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" \
        | jq -r ".assets[] | select(.name | test(\"$pat\")) | .browser_download_url" | head -1)
  if [ -z "$url" ] || [ "$url" = "null" ]; then echo "  !! $name 下载地址解析失败,请手动装"; return; fi
  echo "  下载 $name"
  curl -fsSL "$url" -o "/tmp/$name.zip" 2>/dev/null || curl -fsSL "$url" -o "/tmp/$name.zip"
  unzip -o -q "/tmp/$name.zip" -d "/tmp/${name}_x"
  find "/tmp/${name}_x" -name "$name" -type f -exec cp {} "$BIN_DIR/$name" \; -quit
  chmod +x "$BIN_DIR/$name"; rm -rf "/tmp/$name.zip" "/tmp/${name}_x"
}
dl subfinder projectdiscovery/subfinder "linux_${ARCH}.zip"
dl httpx     projectdiscovery/httpx     "linux_${ARCH}.zip"
dl naabu     projectdiscovery/naabu     "linux_${ARCH}.zip"
dl nuclei    projectdiscovery/nuclei    "linux_${ARCH}.zip"
dl katana    projectdiscovery/katana    "linux_${ARCH}.zip"
dl gau       lc/gau                     "linux_${ARCH}.zip"
"$BIN_DIR/nuclei" -update-templates >/dev/null 2>&1 || true

echo "==> [4/6] python venv + 依赖"
python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q openai pydantic pyyaml tldextract
chmod +x plugins/*/*.py 2>/dev/null || true

echo "==> [5/6] 配置两个 key"
# 仓库里只有 *.example 模板(config.yaml/targets.txt 被 gitignore),首次部署从模板生成
[ -f config.yaml ] || cp config.example.yaml config.yaml
[ -f targets.txt ] || cp targets.example.txt targets.txt
if grep -q 'api_key: ""' config.yaml; then
  LLM_KEY="${ASM_LLM_KEY:-}"
  PUSH_WH="${ASM_PUSH_WEBHOOK:-}"
  if [ -z "$LLM_KEY" ] && [ -t 0 ]; then read -rp "LLM API key: " LLM_KEY; fi
  if [ -z "$PUSH_WH" ] && [ -t 0 ]; then read -rp "钉钉 webhook(可留空): " PUSH_WH; fi
  [ -n "$LLM_KEY" ] && sed -i "s|api_key: \"\"|api_key: \"$LLM_KEY\"|" config.yaml
  [ -n "$PUSH_WH" ] && sed -i "s|webhook: \"\"|webhook: \"$PUSH_WH\"|" config.yaml
fi

echo "==> [6/6] systemd timer"
sudo tee /etc/systemd/system/asm.service >/dev/null <<EOF
[Unit]
Description=asm asset monitoring
After=network-online.target
[Service]
Type=oneshot
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python -m asm run
Environment=HTTPS_PROXY=${HTTPS_PROXY:-}
EOF
CRON=$(grep -E '^run:' schedule.yaml | sed -E 's/run:\s*"([^"]+)"/\1/')
# cron -> systemd OnCalendar(简单转换:分 时 日 月 周)
read -r MI HH DM MO DW <<<"$CRON"
ONCAL="*-${MO:-*}-${DM:-*} ${HH:-*}:${MI:-0}:00"
sudo tee /etc/systemd/system/asm.timer >/dev/null <<EOF
[Unit]
Description=asm timer
[Timer]
OnCalendar=$ONCAL
Persistent=true
[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now asm.timer

sudo tee /usr/local/bin/asm >/dev/null <<EOF
#!/usr/bin/env bash
cd $INSTALL_DIR && exec .venv/bin/python -m asm "\$@"
EOF
sudo chmod +x /usr/local/bin/asm

echo ""
echo "✅ 部署完成"
echo "  加目标:   asm targets add example.com   (或编辑 $INSTALL_DIR/targets.txt)"
echo "  手动跑:   asm run           首轮建基线: asm run --dry"
echo "  看状态:   asm status"
