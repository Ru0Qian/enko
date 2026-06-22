# Enko 部署指南 (Ubuntu 22.04 / 24.04)

> 想部署到 CentOS/Rocky/AlmaLinux 看 [DEPLOY.md](DEPLOY.md)。

## 一键部署

在一台干净的 Ubuntu 22.04 或 24.04 服务器上执行(需 root 权限):

```bash
# 1. 上传或克隆项目源码到服务器
scp -r ./enko/ root@your-server:/root/
#  或:  git clone <your-repo-url> /root/enko

# 2. SSH 登录
ssh root@your-server

# 3. 跑一键部署
cd /root/enko
chmod +x deploy/setup.sh
sudo bash deploy/setup.sh
```

部署完成后,屏幕上会打印:

- 访问地址 `http://<server-ip>/`
- 管理员账号 `admin` + **随机生成的初始密码**(也保存在 `/etc/enko/.admin_password`)

**第一次登录后立即修改密码**,然后 `rm /etc/enko/.admin_password`。

## 脚本做了什么

| 步骤 | 内容 |
|---|---|
| 1 | `apt-get` 安装 Python 3 / JDK 17 / Nginx / unzip / build-essential |
| 1b | 安装 PostgreSQL(Ubuntu 自带版本),创建 `enko` 用户和库 |
| 2 | 下载 Android SDK cmdline-tools 到 `/opt/android-sdk` |
| 3 | sdkmanager 装 build-tools 35.0.0 和 platform-tools(含 zipalign / apksigner) |
| 4 | sdkmanager 装 NDK 27 |
| 5 | 下载 apktool 到 `/opt/enko/tools/`,创建 `/usr/local/bin/apktool` 包装器 |
| 6 | 创建 `enko` 系统用户(无 shell) |
| 7 | 把项目同步到 `/opt/enko/`(rsync,排除 *.apk / __pycache__ 等) |
| 8 | 在 `/opt/enko/venv/` 装 Python 依赖 |
| 9 | 生成 `/etc/enko/config.env` —— **JWT secret + admin 密码 + 数据库密码均随机** |
| 10 | 装 nginx 配置(`/etc/nginx/sites-available/enko`)+ systemd 单元 + 启动 |

整个过程在 1Gbps 网络下约 5–15 分钟(主要时间花在下载 Android SDK / NDK)。

## 自定义变量

`setup.sh` 顶部的常量可以通过 `env` 覆盖,但默认值适合大多数场景:

```bash
ENKO_INSTALL_DIR="/opt/enko"
ANDROID_SDK_ROOT="/opt/android-sdk"
CMDLINE_TOOLS_VERSION="11076708"
BUILD_TOOLS_VERSION="35.0.0"
NDK_VERSION="27.0.12077973"
APKTOOL_VERSION="2.10.0"
```

要改的话直接编辑 `setup.sh` 顶部的对应行(目前还没接 env 覆盖,RHEL 版才有)。

## 启用 HTTPS(可选)

部署完默认只开 HTTP。要 HTTPS 用 Let's Encrypt:

```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d enko.example.com
```

certbot 会自动改 `/etc/nginx/sites-available/enko` 加上 443 server 和证书路径。

## 常用运维

```bash
# 服务状态
sudo systemctl status enko-web nginx postgresql

# 实时日志
sudo journalctl -u enko-web -f

# 重启服务(改 config.env 后必做)
sudo systemctl restart enko-web

# 编辑配置
sudoedit /etc/enko/config.env

# 数据库交互
sudo -u postgres psql enko
```

## 升级到新版本

```bash
# 1) 同步新代码
cd /root/enko && git pull   # 或者重新 scp

# 2) 重跑脚本(幂等,只重写配置和重启服务)
sudo bash deploy/setup.sh
```

> ⚠️ **重跑会重新生成 JWT secret**,所有用户需要重新登录。
> `/etc/enko/.admin_password` 也会被重写 —— 如果你已经改过密码就在脚本跑之前备份原 config.env。

## 故障排查

| 症状 | 解决方法 |
|---|---|
| `systemctl status enko-web` 显示 failed | `journalctl -u enko-web -n 100` 看 traceback;常见原因:`config.env` 缺字段、PostgreSQL 没启 |
| `502 Bad Gateway` | enko-web 没起来。检查 8036 端口:`ss -tlnp \| grep 8036` |
| 上传 APK 报 `413 Request Entity Too Large` | 改 `/etc/nginx/sites-available/enko` 里的 `client_max_body_size` 然后 `sudo nginx -s reload` |
| WebSocket 断开后立刻报错 | nginx 配置已设 `proxy_read_timeout 86400`,正常应该不会出问题;有问题查 nginx error log |
| pip 安装失败(bcrypt/cryptography) | 检查是否装了 `build-essential` 和 `libffi-dev`,脚本默认已装 |
| Android sdkmanager 卡住 | 网络问题。可加代理:`export https_proxy=http://...` 然后重跑 |
| nginx default site 仍是 Nginx 欢迎页 | 检查 `/etc/nginx/sites-enabled/`,确认 `enko` 是符号链接且 `default` 已删除 |

## 备份与卸载

**备份关键数据:**

```bash
# 数据库
sudo -u postgres pg_dump enko > /var/backups/enko-$(date +%F).sql

# 配置(含密钥)
sudo cp /etc/enko/config.env /var/backups/enko-config-$(date +%F).env
```

`output/` 是历史构建产物,需要的话也备份。

**完全卸载:**

```bash
sudo systemctl disable --now enko-web
sudo rm -f /etc/systemd/system/enko-web.service
sudo rm -f /etc/nginx/sites-enabled/enko /etc/nginx/sites-available/enko
sudo systemctl reload nginx

# 数据库(可选)
sudo -u postgres psql -c "DROP DATABASE enko; DROP USER enko;"

# 文件
sudo userdel enko
sudo rm -rf /opt/enko /opt/android-sdk /usr/local/bin/apktool /etc/enko
```

## 防火墙(ufw)

Ubuntu 默认不开 ufw,如果你启用了 ufw 要放通:

```bash
sudo ufw allow 80/tcp     # HTTP
sudo ufw allow 443/tcp    # HTTPS(用了 certbot 才需要)
# 不要开 8036 给外网 —— Nginx 反代后让它只听 127.0.0.1 是更安全的姿态
```

## 与 RHEL 版本的差异

| 点 | Ubuntu (setup.sh) | RHEL (setup-rhel.sh) |
|---|---|---|
| 包管理 | apt-get | dnf |
| Nginx 配置位置 | `sites-available` + `sites-enabled` 符号链接 | `conf.d/enko.conf` 直接读 |
| PostgreSQL 版本 | distro 自带(14/16,看 Ubuntu 版本) | PGDG 仓库装 PostgreSQL 16 |
| 防火墙 | ufw(手动) | firewalld(自动开 80/443) |
| SELinux | N/A | 自动应用 booleans + chcon |
| Python | python3 / python3-pip / python3-venv | python3.11 / python3.11-devel |
| `--domain` 参数 | 暂不支持(改 nginx-enko.conf 加 server_name) | 支持 `--domain example.com` |

两个脚本生成的 `/etc/enko/config.env` 格式一致,服务运行行为也一致。
