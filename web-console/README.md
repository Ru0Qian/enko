# Enko Web Console

这是当前加固项目的本地网页端 MVP。

这版已经能做的事：
- 配置 `harden_apk.py` 参数
- 在网页里勾选方法保护功能：`Extract / VMP DEX / DEX2C`
- 生成命令预览并复制
- 直接点击“开始加固”，由本地 Python 服务拉起任务
- 查看任务状态、返回码和执行日志
- 导入 `report.json` 做可视化查看
- 展示 Flutter native-core 重点项：`libapp.so`、`libflutter.so`、hook watch targets
- 自动发现本机工具链：`apktool`、`zipalign`、`apksigner`、`ndk`

## 启动方式

在 `d:\Engineering\projects\enko\web-console` 下执行：

```powershell
python .\server.py
```

然后打开：

`http://127.0.0.1:8036`

## 运行方式

1. 填好输入 APK、壳 APK、输出 APK、protection map
2. 确认网页自动带出的 NDK 路径
3. 选择目标类型和风险策略
4. 勾选要保留的方法保护功能
5. 点击“开始加固”
6. 在“本地任务”里看日志和结果

## 自动工具发现

网页端后端会优先尝试这些来源：

1. 仓库内 `tools/apktool.bat`
2. `ANDROID_SDK_ROOT` / `ANDROID_HOME`
3. 常见本机路径，例如 `D:\Env\tool\Android-Sdk`
4. `PATH`

如果找到了工具，命令预览和实际任务都会自动带上：
- `--apktool`
- `--zipalign`
- `--apksigner`
- `--ndk-path`

## 功能选择说明

网页端不会改 `harden_apk.py` 的参数协议。

当你关闭 `Extract / VMP DEX / DEX2C` 中的某一项时，网页端会：

1. 基于原始 `protection map`
2. 生成一个临时过滤后的 map
3. 再把这个临时 map 交给 `harden_apk.py`

这样做的好处是：
- 不需要改现有加固主脚本入口
- 你仍然能保留统一的 protection map 管理方式
- 适合后续把这套网页端升级成正式服务

## 这版定位

这是单机本地版，不是最终服务端架构。

如果后面继续演进，推荐拆成：
- `Next.js` 前端
- `FastAPI` API
- `Celery + Redis` 任务执行
- `PostgreSQL` 任务和报告数据
- `S3 / OSS / COS` 产物存储
