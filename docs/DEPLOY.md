# Enko 部署指南 (RHEL / Rocky / AlmaLinux 9)

## 一键部署

在一台干净的 Rocky 9 / AlmaLinux 9 / RHEL 9 服务器上,以 root 执行:

```bash
# 1. 上传或克隆项目源码
scp -r ./enko/ root@your-server:/root/

# 2. SSH 登录
ssh root@your-server

# 3. 跑一键部署
chmod +x /root/enko/deploy/setup-rhel.sh
bash /root/enko/deploy/setup-rhel.sh
# 或带域名:
# bash /root/enko/deploy/setup-rhel.sh --domain enko.example.com
```

脚本完成后会打印:

- 访问地址(默认 `http://<server-ip>/`)
- 管理员账号 `admin` + 自动生成的随机密码(也保存在 `/etc/enko/.admin_password`)

**首次登录后请立即修改 admin 密码**,然后删除 `/etc/enko/.admin_password`。

## 脚本做了什么

| 步骤 | 内容 |
|---|---|
| 1 | `dnf` 安装 Python 3.11 / JDK 17 / Nginx / firewalld / build-essential |
| 2 | 安装并初始化 PostgreSQL 16(若 distro 默认不带,则启用 PGDG 仓库),创建 `enko` 库和用户,密码随机生成 |
| 3 | 下载 Android SDK cmdline-tools,装 build-tools 35.0.0 / platform-tools / NDK 27 |
| 4 | 下载 apktool 并装到 `/opt/enko-tools/`,创建 `/usr/local/bin/apktool` 包装器 |
| 5 | 创建 `enko` 系统用户(无 shell) |
| 6 | 把项目 rsync 到 `/opt/enko/`,在 `/opt/enko/venv/` 装 Python 依赖 |
| 7 | 生成 `/etc/enko/config.env` —— JWT secret + admin 密码全部随机 |
| 8 | 写 `/etc/nginx/conf.d/enko.conf`,打开 firewalld 80/443,应用 SELinux booleans |
| 9 | 装 `enko-web.service`,`enable` + `restart` |

幂等:重复执行不会破坏数据库,会重写配置文件。

## 自定义环境变量

`setup-rhel.sh` 支持通过环境变量覆盖默认设置:

```bash
ENKO_INSTALL_DIR=/srv/enko \
ANDROID_SDK_ROOT=/srv/android-sdk \
PG_MAJOR=15 \
PYTHON_BIN=python3.12 \
bash deploy/setup-rhel.sh
```

| 变量 | 默认 |
|---|---|
| `ENKO_INSTALL_DIR` | `/opt/enko` |
| `ANDROID_SDK_ROOT` | `/opt/android-sdk` |
| `BUILD_TOOLS_VERSION` | `35.0.0` |
| `NDK_VERSION` | `27.0.12077973` |
| `APKTOOL_VERSION` | `2.10.0` |
| `PG_MAJOR` | `16` |
| `PYTHON_BIN` | `python3.11` |

## HTTPS

部署时**只开 HTTP**(端口 80)。需要 HTTPS:

```bash
dnf install -y certbot python3-certbot-nginx
certbot --nginx -d enko.example.com
```

certbot 会自动改写 `/etc/nginx/conf.d/enko.conf` 加上 443 server 和证书路径。

## 常用运维命令

```bash
# 状态
systemctl status enko-web nginx postgresql-16

# 日志(实时)
journalctl -u enko-web -f

# 重启
systemctl restart enko-web

# 编辑配置(改完要 systemctl restart enko-web 才生效)
sudoedit /etc/enko/config.env

# 数据库交互
sudo -u enko psql -h 127.0.0.1 enko
```

## 升级

代码更新后:

```bash
cd /root/enko
git pull   # 或者重新 scp
sudo bash deploy/setup-rhel.sh
```

脚本会:
- rsync 新代码到 `/opt/enko/`(保留 `output/`、`.job-cache/`)
- 重装 Python 依赖
- 重启 enko-web

`/etc/enko/config.env` 会被**覆盖**,如有自定义改动请先备份。JWT secret 会被重置 —— 用户需要重新登录(token 失效)。

## 故障排查

| 症状 | 检查 |
|---|---|
| `systemctl status enko-web` 显示 failed | `journalctl -u enko-web -n 100` 看 traceback;常见原因:`config.env` 缺字段、PostgreSQL 没启 |
| `502 Bad Gateway` | enko-web 没起来。检查 8036 端口:`ss -tlnp \| grep 8036` |
| 上传 APK 报 `413 Request Entity Too Large` | 改 `/etc/nginx/conf.d/enko.conf` 里的 `client_max_body_size` |
| WebSocket 断开后立刻报错 | 检查 nginx `/api/jobs/.../ws` location 的 `proxy_read_timeout`;默认 86400 (24h) |
| SELinux 拒绝 nginx 连后端 | `setsebool -P httpd_can_network_connect 1`(脚本会自动做,异常环境可手动) |
| pip 安装 `bcrypt`/`cryptography` 失败 | 缺 `gcc`/`openssl-devel`(脚本已装),手动:`dnf install -y gcc openssl-devel libffi-devel` |
| Android sdkmanager 卡住 | 网络问题。可设代理:`export https_proxy=...` 后重跑 |

## 备份

最重要的两个文件:

```bash
# 数据库
sudo -u postgres pg_dump enko > /var/backups/enko-$(date +%F).sql

# 配置(含密钥)
cp /etc/enko/config.env /var/backups/enko-config-$(date +%F).env
```

`output/` 是历史构建产物,可选备份。

## 卸载

```bash
systemctl disable --now enko-web
rm -f /etc/systemd/system/enko-web.service
rm -f /etc/nginx/conf.d/enko.conf
systemctl reload nginx

# 留数据库: 想清理就 sudo -u postgres psql -c "DROP DATABASE enko; DROP USER enko;"
# 留配置:   想清理就 rm -rf /etc/enko/

userdel enko
rm -rf /opt/enko /opt/android-sdk /opt/enko-tools /usr/local/bin/apktool
```
