#!/usr/bin/env bash
# ============================================================================
# Enko APK Hardening — RHEL/Rocky/AlmaLinux One-Click Deployment
# Tested on: Rocky Linux 9 / AlmaLinux 9 / RHEL 9
#
# Usage:
#   chmod +x deploy/setup-rhel.sh
#   sudo bash deploy/setup-rhel.sh [--domain example.com]
#
# What this script does:
#   1. Install dnf packages (Python 3.11, JDK 17, Nginx, PostgreSQL 16, ...)
#   2. Initialize PostgreSQL 16 (db cluster + enko db + enko user)
#   3. Download & install Android SDK command-line tools + build-tools + NDK
#   4. Download & install apktool
#   5. Create 'enko' system user
#   6. Copy project to /opt/enko + Python venv + dependencies
#   7. Generate /etc/enko/config.env with random JWT secret + admin password
#   8. Install Nginx config (conf.d) + open firewalld
#   9. Install systemd service & enable + start
#
# Idempotent: re-running re-applies config but does not destroy data.
# ============================================================================

set -euo pipefail

# ---- Colors / helpers ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }
step()  { echo; echo -e "${CYAN}━━━ $* ━━━${NC}"; }

# ---- Parse flags ----
ENKO_DOMAIN=""
for arg in "$@"; do
    case "$arg" in
        --domain=*) ENKO_DOMAIN="${arg#*=}" ;;
        --domain)   shift; ENKO_DOMAIN="${1:-}" ;;
    esac
done

# ---- Must be root ----
[[ $EUID -eq 0 ]] || fail "请以 root 运行: sudo bash $0"

# ---- Detect distro ----
if [[ ! -f /etc/os-release ]]; then
    fail "/etc/os-release 缺失，无法识别发行版"
fi
. /etc/os-release
case "${ID:-}" in
    rocky|almalinux|rhel|centos|ol)
        ok "detected: ${PRETTY_NAME:-${ID}}"
        ;;
    *)
        warn "non-RHEL family detected (${ID}); 仍将尝试 dnf 路径"
        ;;
esac
MAJOR="${VERSION_ID%%.*}"
if [[ "$MAJOR" != "8" && "$MAJOR" != "9" && "$MAJOR" != "10" ]]; then
    warn "未在该 RHEL 大版本测试 (${VERSION_ID}); 继续执行"
fi

# ---- Config (override via env if needed) ----
ENKO_INSTALL_DIR="${ENKO_INSTALL_DIR:-/opt/enko}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-/opt/android-sdk}"
CMDLINE_TOOLS_VERSION="${CMDLINE_TOOLS_VERSION:-11076708}"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip"
BUILD_TOOLS_VERSION="${BUILD_TOOLS_VERSION:-35.0.0}"
NDK_VERSION="${NDK_VERSION:-27.0.12077973}"
APKTOOL_VERSION="${APKTOOL_VERSION:-2.10.0}"
APKTOOL_URL="https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar"
PG_MAJOR="${PG_MAJOR:-16}"
PYTHON_BIN="${PYTHON_BIN:-python3.11}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "════════════════════════════════════════════"
echo "  Enko APK Hardening — RHEL 一键部署"
echo "════════════════════════════════════════════"
info "源码目录:    $SOURCE_DIR"
info "安装目录:    $ENKO_INSTALL_DIR"
info "SDK 目录:    $ANDROID_SDK_ROOT"
info "PostgreSQL:  $PG_MAJOR"
info "域名:        ${ENKO_DOMAIN:-未配置（按 IP 直连）}"
echo ""

# ============================================================================
# Step 1: System packages (dnf)
# ============================================================================
step "Step 1/9: 安装系统依赖"

# Make sure CRB / EPEL is available for some build deps.
dnf install -y -q dnf-plugins-core epel-release >/dev/null 2>&1 || true
if dnf config-manager --help >/dev/null 2>&1; then
    if [[ "$MAJOR" == "9" || "$MAJOR" == "10" ]]; then
        dnf config-manager --set-enabled crb 2>/dev/null || true
    elif [[ "$MAJOR" == "8" ]]; then
        dnf config-manager --set-enabled powertools 2>/dev/null || true
    fi
fi

dnf install -y -q \
    "${PYTHON_BIN}" "${PYTHON_BIN}-devel" "${PYTHON_BIN}-pip" \
    java-17-openjdk-headless \
    nginx \
    unzip wget curl git tar which \
    gcc gcc-c++ make \
    openssl-devel libffi-devel \
    firewalld policycoreutils-python-utils \
    >/dev/null

# Verify
"${PYTHON_BIN}" --version >/dev/null 2>&1 || fail "${PYTHON_BIN} 安装失败"
java -version 2>&1 | head -1 || fail "JDK 安装失败"
ok "系统依赖安装完成"

# ============================================================================
# Step 2: PostgreSQL ${PG_MAJOR}
# ============================================================================
step "Step 2/9: 安装并初始化 PostgreSQL ${PG_MAJOR}"

# Add PGDG repo if PG_MAJOR is not in the default repos.
if ! dnf list installed "postgresql${PG_MAJOR}-server" >/dev/null 2>&1; then
    info "  添加 PGDG 仓库..."
    PGDG_URL="https://download.postgresql.org/pub/repos/yum/reporpms/EL-${MAJOR}-x86_64/pgdg-redhat-repo-latest.noarch.rpm"
    dnf install -y -q "$PGDG_URL" >/dev/null 2>&1 || warn "PGDG 仓库添加失败，回退使用 distro 默认包"

    # Disable built-in postgresql module to avoid conflict (EL 8/9).
    dnf -qy module disable postgresql >/dev/null 2>&1 || true

    # Install PG_MAJOR if available, else fall back to distro postgresql-server.
    if dnf install -y -q "postgresql${PG_MAJOR}-server" "postgresql${PG_MAJOR}-contrib" >/dev/null 2>&1; then
        PG_SERVICE="postgresql-${PG_MAJOR}"
        PG_DATA="/var/lib/pgsql/${PG_MAJOR}/data"
        PG_BIN="/usr/pgsql-${PG_MAJOR}/bin"
    else
        dnf install -y -q postgresql-server postgresql-contrib >/dev/null
        PG_SERVICE="postgresql"
        PG_DATA="/var/lib/pgsql/data"
        PG_BIN="/usr/bin"
    fi
else
    PG_SERVICE="postgresql-${PG_MAJOR}"
    PG_DATA="/var/lib/pgsql/${PG_MAJOR}/data"
    PG_BIN="/usr/pgsql-${PG_MAJOR}/bin"
fi

# Initialize cluster if needed (idempotent — only on first install).
if [[ ! -s "${PG_DATA}/PG_VERSION" ]]; then
    info "  初始化数据库集群 (${PG_DATA})..."
    "${PG_BIN}/postgresql-${PG_MAJOR}-setup" initdb 2>/dev/null \
        || /usr/bin/postgresql-setup --initdb 2>/dev/null \
        || fail "PostgreSQL initdb 失败"
fi

systemctl enable --now "${PG_SERVICE}" >/dev/null
sleep 1

# Configure pg_hba.conf for local md5 (idempotent).
PG_HBA="${PG_DATA}/pg_hba.conf"
if [[ -f "$PG_HBA" ]] && ! grep -q "^# Enko-managed" "$PG_HBA"; then
    info "  配置 pg_hba.conf 允许本地 md5..."
    cp "$PG_HBA" "${PG_HBA}.enko.bak"
    sed -i 's/^\(local\s\+all\s\+all\s\+\)ident$/\1md5/' "$PG_HBA"
    sed -i 's/^\(local\s\+all\s\+all\s\+\)peer$/\1md5/' "$PG_HBA"
    sed -i 's|^\(host\s\+all\s\+all\s\+127\.0\.0\.1/32\s\+\)ident$|\1md5|' "$PG_HBA"
    echo "# Enko-managed pg_hba modifications applied $(date -Iseconds)" >> "$PG_HBA"
    systemctl restart "${PG_SERVICE}"
    sleep 1
fi

# Create/refresh enko role + database. Random db password.
DB_PASS_FILE="/etc/enko/.db_password"
mkdir -p /etc/enko && chmod 700 /etc/enko
if [[ ! -s "$DB_PASS_FILE" ]]; then
    openssl rand -hex 24 > "$DB_PASS_FILE"
    chmod 600 "$DB_PASS_FILE"
    info "  生成随机数据库密码"
fi
DB_PASS="$(cat "$DB_PASS_FILE")"

sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='enko'" | grep -q 1 \
    && sudo -u postgres psql -c "ALTER USER enko WITH PASSWORD '${DB_PASS}';" >/dev/null \
    || sudo -u postgres psql -c "CREATE USER enko WITH PASSWORD '${DB_PASS}';" >/dev/null

sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='enko'" | grep -q 1 \
    || sudo -u postgres psql -c "CREATE DATABASE enko OWNER enko;" >/dev/null
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE enko TO enko;" >/dev/null
ok "PostgreSQL 配置完成: database=enko, user=enko"

# ============================================================================
# Step 3: Android SDK + NDK + build-tools
# ============================================================================
step "Step 3/9: 安装 Android SDK / build-tools ${BUILD_TOOLS_VERSION} / NDK ${NDK_VERSION}"

mkdir -p "$ANDROID_SDK_ROOT/cmdline-tools"

if [[ ! -d "$ANDROID_SDK_ROOT/cmdline-tools/latest/bin" ]]; then
    TMPZIP="$(mktemp /tmp/cmdline-tools.XXXXXX.zip)"
    info "  下载 cmdline-tools..."
    wget -q -O "$TMPZIP" "$CMDLINE_TOOLS_URL" || fail "cmdline-tools 下载失败"
    TMPDIR_EXTRACT="$(mktemp -d /tmp/cmdline-tools-extract.XXXXXX)"
    unzip -q -o "$TMPZIP" -d "$TMPDIR_EXTRACT"
    mv "${TMPDIR_EXTRACT}/cmdline-tools" "$ANDROID_SDK_ROOT/cmdline-tools/latest"
    rm -rf "$TMPZIP" "$TMPDIR_EXTRACT"
    ok "  cmdline-tools 安装完成"
else
    ok "  cmdline-tools 已存在，跳过"
fi

export ANDROID_SDK_ROOT
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$PATH"

# Accept all SDK licenses non-interactively.
yes 2>/dev/null | sdkmanager --licenses >/dev/null 2>&1 || true

info "  安装 build-tools / platform-tools / NDK..."
sdkmanager --install \
    "build-tools;${BUILD_TOOLS_VERSION}" \
    "platform-tools" \
    "ndk;${NDK_VERSION}" \
    >/dev/null 2>&1 || fail "sdkmanager 安装失败"
ok "Android 工具链安装完成"

# ============================================================================
# Step 4: apktool
# ============================================================================
step "Step 4/9: 安装 apktool ${APKTOOL_VERSION}"

APKTOOL_JAR_DIR="/opt/enko-tools"
APKTOOL_JAR="${APKTOOL_JAR_DIR}/apktool_${APKTOOL_VERSION}.jar"
APKTOOL_WRAPPER="/usr/local/bin/apktool"
mkdir -p "$APKTOOL_JAR_DIR"

if [[ ! -s "$APKTOOL_JAR" ]]; then
    wget -q -O "$APKTOOL_JAR" "$APKTOOL_URL" || fail "apktool 下载失败"
fi

cat > "$APKTOOL_WRAPPER" <<'WRAPPER'
#!/usr/bin/env bash
exec java -jar "$(ls /opt/enko-tools/apktool_*.jar 2>/dev/null | head -1)" "$@"
WRAPPER
chmod +x "$APKTOOL_WRAPPER"
ok "apktool 安装完成 ($APKTOOL_WRAPPER)"

# ============================================================================
# Step 5: enko user
# ============================================================================
step "Step 5/9: 创建 enko 系统用户"

if ! id -u enko &>/dev/null; then
    useradd --system --shell /sbin/nologin --home-dir "$ENKO_INSTALL_DIR" --create-home enko
    ok "用户 enko 创建完成"
else
    ok "用户 enko 已存在"
fi

# ============================================================================
# Step 6: Copy project + Python venv
# ============================================================================
step "Step 6/9: 复制项目并安装 Python 依赖"

mkdir -p "$ENKO_INSTALL_DIR"
if command -v rsync &>/dev/null; then
    info "  使用 rsync 同步..."
    rsync -a --delete \
        --exclude='*.apk' \
        --exclude='*.idsig' \
        --exclude='_stitch_tmp' \
        --exclude='_tmp_*' \
        --exclude='.idea' \
        --exclude='__pycache__' \
        --exclude='venv' \
        --exclude='output' \
        --exclude='*.pyc' \
        "$SOURCE_DIR/" "$ENKO_INSTALL_DIR/" || fail "项目同步失败"
else
    info "  rsync 不可用，使用 cp -a..."
    cp -a "$SOURCE_DIR/." "$ENKO_INSTALL_DIR/" || fail "项目复制失败"
fi

mkdir -p "$ENKO_INSTALL_DIR/output" "$ENKO_INSTALL_DIR/web-console/.job-cache"

VENV_DIR="$ENKO_INSTALL_DIR/venv"
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    info "  创建 venv..."
    "${PYTHON_BIN}" -m venv "$VENV_DIR" || fail "venv 创建失败"
fi
"${VENV_DIR}/bin/pip" install --upgrade pip -q
"${VENV_DIR}/bin/pip" install -r "$ENKO_INSTALL_DIR/deploy/requirements.txt" -q || fail "pip install 失败"
ok "Python 依赖安装完成"

# ============================================================================
# Step 7: config.env (with random JWT + admin password)
# ============================================================================
step "Step 7/9: 生成 /etc/enko/config.env"

ADMIN_PASS_FILE="/etc/enko/.admin_password"
if [[ ! -s "$ADMIN_PASS_FILE" ]]; then
    openssl rand -hex 12 > "$ADMIN_PASS_FILE"
    chmod 600 "$ADMIN_PASS_FILE"
fi
ADMIN_PASS="$(cat "$ADMIN_PASS_FILE")"

JWT_SECRET="$(openssl rand -hex 32)"
NDK_PATH="$ANDROID_SDK_ROOT/ndk/${NDK_VERSION}"

if [[ -d "/usr/lib/jvm/java-17-openjdk" ]]; then
    JAVA_HOME_DIR="/usr/lib/jvm/java-17-openjdk"
else
    JAVA_HOME_DIR="$(readlink -f "$(command -v java)" | sed 's|/bin/java||')"
fi

cat > /etc/enko/config.env <<ENVFILE
# Enko Web Console — 自动生成配置
# 生成时间: $(date -Iseconds)
# 主机:     $(hostname)

# ---- 项目路径 ----
ENKO_REPO_ROOT=${ENKO_INSTALL_DIR}
ENKO_WEB_ROOT=${ENKO_INSTALL_DIR}/web-console

# ---- 服务绑定 ----
ENKO_HOST=127.0.0.1
ENKO_PORT=8036
ENKO_WORKERS=2

# ---- JWT (32-byte random hex) ----
ENKO_JWT_SECRET=${JWT_SECRET}
ENKO_JWT_EXPIRE_HOURS=24

# ---- 管理员账号 (首次部署随机生成，已写入 /etc/enko/.admin_password) ----
ENKO_ADMIN_USER=admin
ENKO_ADMIN_PASS=${ADMIN_PASS}

# ---- 数据库 ----
ENKO_DATABASE_URL=postgresql://enko:${DB_PASS}@localhost:5432/enko

# ---- Android 工具链 ----
ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT}
ANDROID_HOME=${ANDROID_SDK_ROOT}
ANDROID_NDK_HOME=${NDK_PATH}
PATH=${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/build-tools/${BUILD_TOOLS_VERSION}:${ANDROID_SDK_ROOT}/platform-tools:/usr/local/bin:/usr/bin:/bin
JAVA_HOME=${JAVA_HOME_DIR}

# ---- Security / runtime ----
ENKO_PRODUCTION=true
ENKO_MAX_CONCURRENT_JOBS=3
ENKO_UPLOAD_TTL_HOURS=24
ENKO_JOB_TTL_DAYS=7
ENVFILE

chmod 600 /etc/enko/config.env
chown root:enko /etc/enko/config.env
ok "config.env 生成完成"

# ============================================================================
# Step 8: Nginx + firewalld + SELinux
# ============================================================================
step "Step 8/9: 配置 Nginx 和防火墙"

NGINX_CONF="/etc/nginx/conf.d/enko.conf"
SERVER_NAME="${ENKO_DOMAIN:-_}"

# Render the nginx config from a template file in deploy/.
# Replace ${SERVER_NAME} and ${ENKO_INSTALL_DIR} at write time.
sed -e "s|@SERVER_NAME@|${SERVER_NAME}|g" \
    -e "s|@ENKO_INSTALL_DIR@|${ENKO_INSTALL_DIR}|g" \
    "$ENKO_INSTALL_DIR/deploy/nginx-enko-rhel.conf" \
    > "$NGINX_CONF"

# Remove RHEL default server block if present (so default_server works).
if [[ -f /etc/nginx/conf.d/default.conf ]]; then
    mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.enko-disabled
fi

nginx -t 2>&1 | sed 's/^/    /'
if ! nginx -t >/dev/null 2>&1; then
    fail "Nginx 配置校验失败 (见上)"
fi

if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
    setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    chcon -Rt httpd_sys_content_t "$ENKO_INSTALL_DIR/web-console" 2>/dev/null || true
    info "  SELinux booleans/labels applied"
fi

systemctl enable --now nginx >/dev/null
systemctl reload nginx
ok "Nginx 配置完成 ($NGINX_CONF)"

if systemctl is-active --quiet firewalld; then
    firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "firewalld 已开放 80/443"
else
    warn "firewalld 未运行，跳过端口规则"
fi

# ============================================================================
# Step 9: systemd service
# ============================================================================
step "Step 9/9: 安装 systemd 服务"

cp "$ENKO_INSTALL_DIR/deploy/enko-web.service" /etc/systemd/system/enko-web.service

chown -R enko:enko "$ENKO_INSTALL_DIR"
chown -R enko:enko "$ANDROID_SDK_ROOT"

systemctl daemon-reload
systemctl enable enko-web >/dev/null
systemctl restart enko-web

sleep 3
if systemctl is-active --quiet enko-web; then
    ok "enko-web 服务运行正常"
else
    warn "enko-web 启动可能异常，请检查: journalctl -u enko-web -n 80"
fi

# ============================================================================
# Done
# ============================================================================
SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[[ -z "$SERVER_IP" ]] && SERVER_IP="$(ip route get 1 2>/dev/null | awk '{print $7; exit}')"
SERVER_IP="${SERVER_IP:-<server-ip>}"

echo ""
echo "════════════════════════════════════════════"
echo -e "  ${GREEN}✅ Enko 部署完成${NC}"
echo "════════════════════════════════════════════"
echo
echo "  🌐 访问地址:  http://${ENKO_DOMAIN:-$SERVER_IP}/"
echo "  👤 管理员:    admin"
echo "  🔑 初始密码:  $ADMIN_PASS"
echo "                (也存于 /etc/enko/.admin_password，建议登录后立即修改)"
echo
echo "  📋 常用命令:"
echo "     状态:  systemctl status enko-web nginx postgresql-${PG_MAJOR}"
echo "     日志:  journalctl -u enko-web -f"
echo "     重启:  systemctl restart enko-web"
echo "     配置:  sudoedit /etc/enko/config.env"
echo
echo "  🔧 Android 工具链:"
echo "     SDK:     $ANDROID_SDK_ROOT"
echo "     NDK:     $NDK_PATH"
echo "     apktool: $APKTOOL_WRAPPER"
echo
echo -e "  ${YELLOW}⚠️  生产环境必做:${NC}"
echo "     1) 立刻登录修改 admin 密码"
echo "     2) 如需 HTTPS，安装 certbot: dnf install -y certbot python3-certbot-nginx"
echo "        然后: certbot --nginx -d your.domain.com"
echo "     3) 删除 /etc/enko/.admin_password (备份后)"
echo
