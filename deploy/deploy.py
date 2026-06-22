"""Enko deployment script — sync code to server via SFTP."""
import paramiko
import os
import sys

HOST = "113.44.64.117"
PORT = 22
USER = "root"
PASSWORD = "Gongqwe123"
REMOTE_DIR = "/opt/enko"
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    # web-console
    "web-console/index.html",
    "web-console/index-visual.html",
    "web-console/index-legacy.html",
    "web-console/app.js",
    "web-console/app-legacy.js",
    "web-console/styles.css",
    "web-console/server.py",
    "web-console/server_prod.py",
    "web-console/common.py",
    "web-console/enko-hardening-features.json",
    "web-console/js/utils.js",
    "web-console/js/api.js",
    "web-console/js/analyzer.js",
    # packer
    "packer/harden_apk.py",
    "packer/dex_parser.py",
    "packer/dex_writer.py",
    "packer/method_extractor.py",
    "packer/vmp_compiler.py",
    "packer/vmp_stub_gen.py",
    "packer/auto_protect_map.py",
    "packer/release_manifest_tool.py",
    "packer/dex2c/__init__.py",
    "packer/dex2c/compiler.py",
    "packer/dex2c/translator.py",
    # deploy configs
    "deploy/requirements.txt",
    "deploy/nginx-enko.conf",
    "deploy/enko-web.service",
    "deploy/enko-db-backup.service",
    "deploy/enko-db-backup.timer",
    "deploy/enko-db-backup.sh",
    "deploy/config.env.example",
    "deploy/setup.sh",
]


def main():
    print("=" * 50)
    print("  Enko — 代码部署")
    print("=" * 50)
    print(f"\n  服务器: {USER}@{HOST}:{PORT}")
    print(f"  项目目录: {PROJECT_ROOT}")
    print(f"  文件数: {len(FILES)}")
    print()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(HOST, port=PORT, username=USER, password=PASSWORD, timeout=15)
        print("[OK] SSH 连接成功\n")
    except Exception as e:
        print(f"[FAIL] SSH 连接失败: {e}")
        sys.exit(1)

    sftp = client.open_sftp()

    # Ensure remote directories exist
    dirs = [
        f"{REMOTE_DIR}/web-console/js",
        f"{REMOTE_DIR}/packer/dex2c",
        f"{REMOTE_DIR}/deploy",
    ]
    for d in dirs:
        try:
            sftp.stat(d)
        except FileNotFoundError:
            print(f"[INFO] 创建远程目录: {d}")
            sftp.mkdir(d)

    # Upload files
    success = 0
    failed = []

    for path in FILES:
        local = os.path.join(PROJECT_ROOT, path.replace("/", os.sep))
        remote = f"{REMOTE_DIR}/{path}"

        if not os.path.exists(local):
            print(f"[WARN] 跳过 (本地不存在): {path}")
            failed.append(path)
            continue

        try:
            sftp.put(local, remote)
            success += 1
            print(f"  [OK] {path}")
        except Exception as e:
            print(f"  [FAIL] {path} — {e}")
            failed.append(path)

    sftp.close()

    print(f"\n[INFO] 上传完成: {success}/{len(FILES)} 成功, {len(failed)} 失败")

    # Restart service
    print("\n[INFO] 重启 enko-web 服务...")
    restart_cmd = (
        f"chown -R enko:enko {REMOTE_DIR} 2>/dev/null; "
        f"cp {REMOTE_DIR}/deploy/nginx-enko.conf /etc/nginx/sites-available/enko 2>/dev/null; "
        f"nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null; "
        f"cp {REMOTE_DIR}/deploy/enko-web.service /etc/systemd/system/; "
        f"systemctl daemon-reload; "
        f"systemctl restart enko-web; "
        f"sleep 2; "
        f"if systemctl is-active --quiet enko-web; then "
        f"  echo '[OK] enko-web 服务运行正常'; "
        f"else "
        f"  echo '[WARN] enko-web 可能有问题'; journalctl -u enko-web -n 10 --no-pager; "
        f"fi"
    )

    stdin, stdout, stderr = client.exec_command(restart_cmd)
    print(stdout.read().decode())
    err = stderr.read().decode()
    if err:
        print(f"[STDERR]: {err}")

    client.close()
    print("\n" + "=" * 50)
    print("  [OK] 部署完成!")
    print(f"  访问: http://{HOST}")
    print("=" * 50)


if __name__ == "__main__":
    main()
