@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

:: ============================================================================
:: Enko — Windows 代码更新脚本
:: 仅同步代码文件到服务器（工具链由 setup.sh 首次部署，无需重复同步）
::
:: Usage: 双击运行 或 在 CMD/PowerShell 中执行:
::   deploy\update.bat
:: ============================================================================

set REMOTE_USER=root
set REMOTE_HOST=%ENKO_DEPLOY_HOST%
if "%REMOTE_HOST%"=="" (
    echo [ERROR] 环境变量 ENKO_DEPLOY_HOST 未设置！
    echo [HINT]  请先运行: set ENKO_DEPLOY_HOST=你的服务器IP
    pause
    exit /b 1
)
set REMOTE_DIR=/opt/enko
set SSH_PORT=22

:: SSH 密钥检测
set SSH_KEY_OPT=
if defined ENKO_SSH_KEY (
    set SSH_KEY_OPT=-i "%ENKO_SSH_KEY%"
) else if exist "%USERPROFILE%\.ssh\id_ed25519" (
    set SSH_KEY_OPT=-i "%USERPROFILE%\.ssh\id_ed25519"
) else if exist "%USERPROFILE%\.ssh\id_rsa" (
    set SSH_KEY_OPT=-i "%USERPROFILE%\.ssh\id_rsa"
)

:: 找到项目根目录
set "SCRIPT_DIR=%~dp0"
set "SOURCE_DIR=%SCRIPT_DIR%.."
cd /d "%SOURCE_DIR%"

echo.
echo ==========================================
echo   Enko — 代码更新
echo ==========================================
echo.
echo [INFO] 本地源码: %CD%
echo [INFO] 远程目标: %REMOTE_USER%@%REMOTE_HOST%:%REMOTE_DIR%
echo.
echo   即将部署以下内容到远程服务器：
echo     - web-console  (前端 UI + 后端 API)
echo     - packer       (加固引擎代码)
echo     - deploy       (Nginx/systemd/依赖/配置)
echo.
set /p CONFIRM="确认部署？ (y/N): "
if /i not "%CONFIRM%"=="y" (
    echo [INFO] 已取消部署
    exit /b 0
)
echo.

:: ---- Step 0: 确保远程目录存在 ----
echo [INFO] 确保远程目录结构...
ssh %SSH_KEY_OPT% -p %SSH_PORT% %REMOTE_USER%@%REMOTE_HOST% "mkdir -p %REMOTE_DIR%/web-console/js %REMOTE_DIR%/packer/dex2c"

:: ---- Step 1: web-console（前端 UI + 后端 API）----
echo [INFO] [1/3] 同步 web-console ...
scp %SSH_KEY_OPT% -P %SSH_PORT% ^
    "web-console\index.html" ^
    "web-console\index-visual.html" ^
    "web-console\index-legacy.html" ^
    "web-console\app.js" ^
    "web-console\app-legacy.js" ^
    "web-console\styles.css" ^
    "web-console\server.py" ^
    "web-console\server_prod.py" ^
    "web-console\common.py" ^
    "web-console\enko-hardening-features.json" ^
    "web-console\js\utils.js" ^
    "web-console\js\api.js" ^
    "web-console\js\analyzer.js" ^
    %REMOTE_USER%@%REMOTE_HOST%:%REMOTE_DIR%/web-console/
if %ERRORLEVEL% NEQ 0 (
    echo [FAIL] web-console 同步失败！
    echo [HINT] 可能原因: SSH 连接失败 / 目标目录不存在 / 权限不足
    echo [HINT] 尝试: ssh -p %SSH_PORT% %REMOTE_USER%@%REMOTE_HOST% "ls %REMOTE_DIR%"
    pause
    exit /b 1
)
echo [ OK ] web-console 同步完成

:: ---- Step 2: packer（加固引擎 Python 代码）----
echo [INFO] [2/3] 同步 packer ...
scp %SSH_KEY_OPT% -P %SSH_PORT% ^
    "packer\harden_apk.py" ^
    "packer\dex_parser.py" ^
    "packer\dex_writer.py" ^
    "packer\method_extractor.py" ^
    "packer\vmp_compiler.py" ^
    "packer\vmp_stub_gen.py" ^
    "packer\auto_protect_map.py" ^
    "packer\release_manifest_tool.py" ^
    "packer\dex2c\__init__.py" ^
    "packer\dex2c\compiler.py" ^
    "packer\dex2c\translator.py" ^
    %REMOTE_USER%@%REMOTE_HOST%:%REMOTE_DIR%/packer/
echo [ OK ] packer 同步完成

:: ---- Step 3: deploy 配置（如有变更）----
echo [INFO] [3/3] 同步 deploy 配置 ...
scp %SSH_KEY_OPT% -P %SSH_PORT% ^
    "deploy\requirements.txt" ^
    "deploy\nginx-enko.conf" ^
    "deploy\enko-web.service" ^
    "deploy\enko-db-backup.service" ^
    "deploy\enko-db-backup.timer" ^
    "deploy\enko-db-backup.sh" ^
    "deploy\config.env.example" ^
    "deploy\setup.sh" ^
    %REMOTE_USER%@%REMOTE_HOST%:%REMOTE_DIR%/deploy/
echo [ OK ] deploy 配置同步完成

:: ---- Step 4: 远程重启服务 ----
echo.
echo [INFO] 正在重启远程服务...
ssh %SSH_KEY_OPT% -p %SSH_PORT% %REMOTE_USER%@%REMOTE_HOST% "chown -R enko:enko /opt/enko 2>/dev/null; /opt/enko/venv/bin/pip install -q -r /opt/enko/deploy/requirements.txt 2>/dev/null; cp /opt/enko/deploy/nginx-enko.conf /etc/nginx/sites-available/enko; nginx -t 2>/dev/null && systemctl reload nginx; cp /opt/enko/deploy/enko-web.service /etc/systemd/system/enko-web.service; cp /opt/enko/deploy/enko-db-backup.service /etc/systemd/system/; cp /opt/enko/deploy/enko-db-backup.timer /etc/systemd/system/; cp /opt/enko/deploy/enko-db-backup.sh /usr/local/bin/ && chmod +x /usr/local/bin/enko-db-backup.sh; systemctl daemon-reload; systemctl enable --now enko-db-backup.timer 2>/dev/null; systemctl restart enko-web; sleep 2; if systemctl is-active --quiet enko-web; then echo '[ OK ] enko-web 服务运行正常'; else echo '[WARN] enko-web 可能有问题'; journalctl -u enko-web -n 10 --no-pager; fi"

echo.
echo ==========================================
echo   ✅ 代码更新完成！
echo ==========================================
echo.
echo   已同步:
echo     - web-console  (前端 UI + 后端 API)
echo     - packer       (加固引擎代码)
echo     - deploy       (Nginx/systemd/依赖/配置)
echo.
echo   访问: http://%REMOTE_HOST%
echo.
pause
