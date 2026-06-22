#!/usr/bin/env bash
# ============================================================================
# Enko APK Hardening — One-Click Linux Deployment Script
# Tested on: Ubuntu 20.04 / 22.04 / 24.04
#
# Usage:
#   chmod +x deploy/setup.sh
#   sudo bash deploy/setup.sh
#
# What this script does:
#   1. Install system packages (Python 3, JDK 17, Nginx, unzip, etc.)
#   2. Download & install Android SDK command-line tools
#   3. Download & install Android NDK + build-tools (zipalign, apksigner)
#   4. Download & install apktool
#   5. Create 'enko' system user
#   6. Copy project to /opt/enko
#   7. Set up Python venv with all dependencies
#   8. Generate JWT secret & write /etc/enko/config.env
#   9. Install Nginx config (HTTP mode)
#  10. Install systemd service & start
# ============================================================================

set -euo pipefail

# ---- Color helpers ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ---- Must be root ----
[[ $EUID -eq 0 ]] || fail "请以 root 运行: sudo bash $0"

# ---- Config ----
ENKO_INSTALL_DIR="/opt/enko"
ANDROID_SDK_ROOT="/opt/android-sdk"
CMDLINE_TOOLS_VERSION="11076708"  # latest as of 2024
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip"
BUILD_TOOLS_VERSION="35.0.0"
NDK_VERSION="27.0.12077973"
APKTOOL_VERSION="2.10.0"
APKTOOL_URL="https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"

# Detect the source directory (where this script is located)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "=========================================="
echo "  Enko APK Hardening — 一键部署"
echo "=========================================="
echo ""
info "源码目录: $SOURCE_DIR"
info "安装目录: $ENKO_INSTALL_DIR"
info "SDK 目录:  $ANDROID_SDK_ROOT"
echo ""

# ============================================================================
# Step 1: System packages
# ============================================================================
info "Step 1/10: 安装系统依赖..."
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    openjdk-17-jdk-headless \
    nginx \
    unzip wget curl git \
    build-essential \
    > /dev/null 2>&1

# Verify
python3 --version > /dev/null 2>&1 || fail "Python3 安装失败"
java -version 2>&1 | head -1 || fail "JDK 安装失败"
ok "系统依赖安装完成"

# ============================================================================
# Step 1b: Install PostgreSQL
# ============================================================================
info "Step 1b/10: 安装 PostgreSQL..."
apt-get install -y -qq postgresql postgresql-contrib > /dev/null 2>&1
systemctl enable postgresql
systemctl start postgresql

# Create DB user and database (idempotent)
sudo -u postgres psql -c "CREATE USER enko WITH PASSWORD 'enko';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE enko OWNER enko;" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE enko TO enko;" 2>/dev/null || true
ok "PostgreSQL 配置完成: database=enko, user=enko"

# ============================================================================
# Step 2: Android SDK command-line tools
# ============================================================================
info "Step 2/10: 安装 Android SDK command-line tools..."
mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"

if [[ ! -d "$ANDROID_SDK_ROOT/cmdline-tools/latest" ]]; then
    TMPZIP="/tmp/cmdline-tools.zip"
    info "  下载 cmdline-tools..."
    wget -q -O "$TMPZIP" "$CMDLINE_TOOLS_URL"
    unzip -q -o "$TMPZIP" -d "/tmp/cmdline-tools-extract"
    mv "/tmp/cmdline-tools-extract/cmdline-tools" "$ANDROID_SDK_ROOT/cmdline-tools/latest"
    rm -rf "$TMPZIP" "/tmp/cmdline-tools-extract"
    ok "  cmdline-tools 安装完成"
else
    ok "  cmdline-tools 已存在，跳过"
fi

export ANDROID_SDK_ROOT
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$PATH"

# ============================================================================
# Step 3: Accept licenses & install build-tools + platform-tools
# ============================================================================
info "Step 3/10: 安装 build-tools ${BUILD_TOOLS_VERSION} 和 platform-tools..."
yes | sdkmanager --licenses > /dev/null 2>&1 || true
sdkmanager --install \
    "build-tools;${BUILD_TOOLS_VERSION}" \
    "platform-tools" \
    > /dev/null 2>&1
ok "build-tools 和 platform-tools 安装完成"

# ============================================================================
# Step 4: Android NDK
# ============================================================================
info "Step 4/10: 安装 Android NDK ${NDK_VERSION}..."
if [[ ! -d "$ANDROID_SDK_ROOT/ndk/${NDK_VERSION}" ]]; then
    sdkmanager --install "ndk;${NDK_VERSION}" > /dev/null 2>&1
    ok "NDK 安装完成"
else
    ok "NDK 已存在，跳过"
fi

# ============================================================================
# Step 5: apktool
# ============================================================================
info "Step 5/10: 安装 apktool ${APKTOOL_VERSION}..."
APKTOOL_JAR="$ENKO_INSTALL_DIR/tools/apktool_${APKTOOL_VERSION}.jar"
APKTOOL_WRAPPER="/usr/local/bin/apktool"

mkdir -p "$ENKO_INSTALL_DIR/tools"

if [[ ! -f "$APKTOOL_JAR" ]]; then
    wget -q -O "$APKTOOL_JAR" "$APKTOOL_URL"
fi

cat > "$APKTOOL_WRAPPER" << 'WRAPPER'
#!/usr/bin/env bash
exec java -jar /opt/enko/tools/apktool_*.jar "$@"
WRAPPER
chmod +x "$APKTOOL_WRAPPER"
ok "apktool 安装完成"

# ============================================================================
# Step 6: Create enko user
# ============================================================================
info "Step 6/10: 创建 enko 系统用户..."
if ! id -u enko &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir "$ENKO_INSTALL_DIR" enko
    ok "用户 enko 创建完成"
else
    ok "用户 enko 已存在，跳过"
fi

# ============================================================================
# Step 7: Copy project
# ============================================================================
info "Step 7/10: 复制项目到 ${ENKO_INSTALL_DIR}..."
mkdir -p "$ENKO_INSTALL_DIR"

# rsync if available, otherwise cp
if command -v rsync &>/dev/null; then
    rsync -a --delete \
        --exclude='*.apk' \
        --exclude='*.idsig' \
        --exclude='_stitch_tmp' \
        --exclude='_tmp_device_base.apk' \
        --exclude='.idea' \
        --exclude='__pycache__' \
        --exclude='venv' \
        --exclude='output' \
        "$SOURCE_DIR/" "$ENKO_INSTALL_DIR/"
else
    cp -a "$SOURCE_DIR/." "$ENKO_INSTALL_DIR/"
fi

mkdir -p "$ENKO_INSTALL_DIR/output"
mkdir -p "$ENKO_INSTALL_DIR/web-console/.job-cache"
ok "项目复制完成"

# ============================================================================
# Step 8: Python venv & dependencies
# ============================================================================
info "Step 8/10: 创建 Python 虚拟环境并安装依赖..."
VENV_DIR="$ENKO_INSTALL_DIR/venv"

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$ENKO_INSTALL_DIR/deploy/requirements.txt" -q
ok "Python 依赖安装完成"

# ============================================================================
# Step 9: Generate config.env with JWT secret
# ============================================================================
info "Step 9/10: 生成配置文件 /etc/enko/config.env..."
mkdir -p /etc/enko
chmod 700 /etc/enko

# Random admin password (persisted to /etc/enko/.admin_password so the
# operator can read it during first-time setup).
ADMIN_PASS_FILE="/etc/enko/.admin_password"
if [[ ! -s "$ADMIN_PASS_FILE" ]]; then
    openssl rand -hex 12 > "$ADMIN_PASS_FILE"
    chmod 600 "$ADMIN_PASS_FILE"
fi
ADMIN_PASS="$(cat "$ADMIN_PASS_FILE")"

JWT_SECRET="$(openssl rand -hex 32)"
NDK_PATH="$ANDROID_SDK_ROOT/ndk/${NDK_VERSION}"

cat > /etc/enko/config.env << EOF
# Enko Web Console — 自动生成配置
# 生成时间: $(date -Iseconds)

# ---- 项目路径 ----
ENKO_REPO_ROOT=${ENKO_INSTALL_DIR}
ENKO_WEB_ROOT=${ENKO_INSTALL_DIR}/web-console

# ---- 服务绑定 ----
ENKO_HOST=127.0.0.1
ENKO_PORT=8036
ENKO_WORKERS=2

# ---- JWT ----
ENKO_JWT_SECRET=${JWT_SECRET}
ENKO_JWT_EXPIRE_HOURS=24

# ---- 管理员账号（首次部署随机生成，已写入 /etc/enko/.admin_password）----
ENKO_ADMIN_USER=admin
ENKO_ADMIN_PASS=${ADMIN_PASS}

# ---- Android 工具链 ----
ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT}
ANDROID_HOME=${ANDROID_SDK_ROOT}
ANDROID_NDK_HOME=${NDK_PATH}
PATH=${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/build-tools/${BUILD_TOOLS_VERSION}:${ANDROID_SDK_ROOT}/platform-tools:/usr/local/bin:\$PATH
JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
EOF

chmod 600 /etc/enko/config.env

# Generate JWT secret if placeholder is still present (e.g. manual config)
if grep -q "CHANGE_ME_TO_A_RANDOM_64_CHAR_HEX_STRING" /etc/enko/config.env 2>/dev/null; then
    JWT_AUTO="$(openssl rand -hex 32)"
    sed -i "s/CHANGE_ME_TO_A_RANDOM_64_CHAR_HEX_STRING/$JWT_AUTO/" /etc/enko/config.env
    info "自动替换了 JWT 占位符"
fi
ok "配置文件生成完成"

# ============================================================================
# Step 10: Nginx + systemd
# ============================================================================
info "Step 10/10: 配置 Nginx 和 systemd 服务..."

# Nginx
cp "$ENKO_INSTALL_DIR/deploy/nginx-enko.conf" /etc/nginx/sites-available/enko
ln -sf /etc/nginx/sites-available/enko /etc/nginx/sites-enabled/enko
rm -f /etc/nginx/sites-enabled/default

nginx -t 2>&1 || fail "Nginx 配置校验失败"
systemctl restart nginx
systemctl enable nginx
ok "Nginx 配置完成"

# systemd service
cp "$ENKO_INSTALL_DIR/deploy/enko-web.service" /etc/systemd/system/enko-web.service
chown -R enko:enko "$ENKO_INSTALL_DIR"
chown -R enko:enko "$ANDROID_SDK_ROOT"

systemctl daemon-reload
systemctl enable enko-web
systemctl restart enko-web
ok "systemd 服务已启动"

# ============================================================================
# Verify
# ============================================================================
sleep 2
if systemctl is-active --quiet enko-web; then
    ok "enko-web 服务运行正常"
else
    warn "enko-web 服务启动可能有问题，请检查: journalctl -u enko-web -n 50"
fi

# ============================================================================
# Done
# ============================================================================
SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "=========================================="
echo -e "  ${GREEN}✅ Enko 部署完成！${NC}"
echo "=========================================="
echo ""
echo "  🌐 访问地址:  http://${SERVER_IP}"
echo "  👤 管理员用户: admin"
echo "  🔑 管理员密码: ${ADMIN_PASS}"
echo "                  (也保存在 /etc/enko/.admin_password)"
echo ""
echo "  ⚠️  请首次登录后立即修改密码，并删除 /etc/enko/.admin_password"
echo ""
echo "  📋 常用命令:"
echo "     查看服务状态: systemctl status enko-web"
echo "     查看日志:     journalctl -u enko-web -f"
echo "     重启服务:     systemctl restart enko-web"
echo "     编辑配置:     sudoedit /etc/enko/config.env"
echo ""
echo "  🔧 Android 工具链:"
echo "     SDK:  $ANDROID_SDK_ROOT"
echo "     NDK:  $NDK_PATH"
echo "     apktool: $APKTOOL_WRAPPER"
echo ""
echo -e "  ${YELLOW}⚠️  初始密码随机生成，已保存到 /etc/enko/.admin_password；登录后请立即修改并删除该文件！${NC}"
echo ""
