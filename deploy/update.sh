#!/usr/bin/env bash
# ============================================================================
# Enko — 远程更新脚本
# 将本地最新代码同步到已部署的服务器并重启服务
#
# Usage (在本地 Git Bash / WSL / Mac 终端执行):
#   bash deploy/update.sh
#
# 首次运行会要求输入 SSH 密码，建议配好 SSH key 后免密
# ============================================================================

set -euo pipefail

# ---- 配置（从环境变量读取，可在 .env 或 shell 中设置）----
REMOTE_USER="${ENKO_DEPLOY_USER:-root}"
REMOTE_HOST="${ENKO_DEPLOY_HOST:-}"
REMOTE_DIR="${ENKO_DEPLOY_DIR:-/opt/enko}"
SSH_PORT="${ENKO_DEPLOY_SSH_PORT:-22}"

if [[ -z "$REMOTE_HOST" ]]; then
    echo -e "${YELLOW}[ERROR]${NC} 环境变量 ENKO_DEPLOY_HOST 未设置！"
    echo "  请先运行: export ENKO_DEPLOY_HOST=你的服务器IP"
    exit 1
fi

# SSH 密钥自动检测
SSH_KEY_OPT=""
if [[ -n "${ENKO_SSH_KEY:-}" && -f "$ENKO_SSH_KEY" ]]; then
    SSH_KEY_OPT="-i $ENKO_SSH_KEY"
elif [[ -f "$HOME/.ssh/id_ed25519" ]]; then
    SSH_KEY_OPT="-i $HOME/.ssh/id_ed25519"
elif [[ -f "$HOME/.ssh/id_rsa" ]]; then
    SSH_KEY_OPT="-i $HOME/.ssh/id_rsa"
fi
[[ -n "$SSH_KEY_OPT" ]] && info "使用 SSH 密钥: ${SSH_KEY_OPT#-i }"

# 颜色
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

# 找到项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "=========================================="
echo "  Enko — 远程更新"
echo "=========================================="
echo ""
info "本地源码: $SOURCE_DIR"
info "远程目标: ${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}"
echo ""
echo "  即将同步全部代码到远程服务器并重启服务。"
read -rp "  确认部署？ (y/N): " CONFIRM
if [[ "${CONFIRM,,}" != "y" ]]; then
    info "已取消部署"
    exit 0
fi
echo ""

# ---- Step 1: 同步代码 ----
info "正在同步代码到服务器..."

# 使用 rsync 增量同步（只传输变更的文件）
rsync -avz --progress \
    --exclude='*.apk' \
    --exclude='*.idsig' \
    --exclude='_stitch_tmp/' \
    --exclude='_stitch_ref/' \
    --exclude='_tmp_device_base.apk' \
    --exclude='_crash_window.log' \
    --exclude='_window_dump.xml' \
    --exclude='.idea/' \
    --exclude='__pycache__/' \
    --exclude='venv/' \
    --exclude='output/' \
    --exclude='*.jks' \
    --exclude='*.report.json' \
    --exclude='*.log' \
    -e "ssh $SSH_KEY_OPT -p ${SSH_PORT}" \
    "$SOURCE_DIR/" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"

ok "代码同步完成"

# ---- Step 2: 远程重启服务 ----
info "正在重启远程服务..."

ssh $SSH_KEY_OPT -p "${SSH_PORT}" "${REMOTE_USER}@${REMOTE_HOST}" bash -s << 'REMOTE_COMMANDS'
set -euo pipefail

# 修复权限
chown -R enko:enko /opt/enko 2>/dev/null || echo "[WARN] chown failed (may need sudo)"

# 更新 Python 依赖
if [[ -f /opt/enko/deploy/requirements.txt ]]; then
    echo "[INFO] Installing Python dependencies..."
    /opt/enko/venv/bin/pip install -q -r /opt/enko/deploy/requirements.txt || {
        echo "[ERROR] pip install failed!"
        exit 1
    }
fi

# 更新 Nginx 配置并 reload
cp /opt/enko/deploy/nginx-enko.conf /etc/nginx/sites-available/enko
echo "[INFO] Testing nginx config..."
if nginx -t 2>&1; then
    systemctl reload nginx
    echo "[OK] nginx reloaded"
else
    echo "[ERROR] nginx config test failed! Not reloading."
    exit 1
fi

# 更新 systemd service
cp /opt/enko/deploy/enko-web.service /etc/systemd/system/enko-web.service
systemctl daemon-reload

# 重启服务
echo "[INFO] Restarting enko-web..."
systemctl restart enko-web
sleep 2

# 检查状态
if systemctl is-active --quiet enko-web; then
    echo "[OK] enko-web 服务运行正常"
else
    echo "[ERROR] enko-web 服务启动失败！"
    journalctl -u enko-web -n 20 --no-pager
    exit 1
fi
REMOTE_COMMANDS

ok "远程服务已重启"

echo ""
echo "=========================================="
echo -e "  ${GREEN}✅ 更新完成！${NC}"
echo "=========================================="
echo ""
echo "  🌐 访问: http://${REMOTE_HOST}"
echo ""
