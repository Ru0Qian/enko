# Enko 操作手册

## 默认签名流程

Enko 默认输出 `unsigned/aligned` APK，不在加固流水线里重签名。业务方应使用输入 APK 的同一套发布证书重新签名。

仅当你确认加固端持有目标 APK 的原始签名私钥时，才开启 Web UI 的“加固端签名”或 CLI 的 `--sign`。

推荐流程：

```bash
python packer/harden_apk.py \
  --input-apk app-release.apk \
  --shell-apk shell-app/app/build/outputs/apk/release/app-release-unsigned.apk \
  --output-apk app-hardened-unsigned.apk \
  --skip-sign \
  --sign-cert-sha256 <original-cert-sha256>
```

随后用业务发布证书执行 `apksigner sign`。

## OLLVM 配置

Shell native 和 DEX2C 的 `libagpjnix.so` 都支持 Hikari/OLLVM。

服务器默认路径为：

```bash
/opt/enko/toolchains/hikari-llvm19/install/bin/clang
```

首次部署可直接安装 Hikari/LLVM 19：

```bash
cd /opt/enko
bash tools/install_hikari_ollvm.sh

echo "ENKO_OLLVM_CLANG=/opt/enko/toolchains/hikari-llvm19/install/bin/clang" >> /etc/enko/config.env
systemctl restart enko-web
```

DEX2C 默认开启 OLLVM，但默认是 best-effort：如果 `--dex2c-ollvm-clang` 不可用，会回退到普通 NDK clang。强保护或商业发布时使用 required：

```bash
python packer/harden_apk.py \
  --dex2c-ollvm \
  --dex2c-ollvm-clang /opt/enko/toolchains/hikari-llvm19/install/bin/clang \
  --dex2c-ollvm-required
```

报告里检查：

- `method_protection.dex2c_native_obfuscation.ollvm_effective`
- `ollvm_protected_libraries`
- `fallback_used`
- `preflight_status`

## 保护档位

兼容推荐：

- 风险策略偏 `warn/compat`
- 关闭 root/模拟器阻断
- 保留方法抽取、轻量 VMP、多态壳
- 默认不做 DEX2C，避免高频业务逻辑被 native/JNI 边界拖慢

强保护：

- `block/strict`
- 方法抽取、VMP、DEX2C 全开
- Shell VMP、多态壳、DEX 页封存全开
- DEX2C OLLVM required

Web UI 的”兼容推荐”和”强保护”按钮会自动套这些参数，且保留当前 Android/Flutter 目标。

## 运行时风险分级响应（P6-1）

壳运行时不再”检测到风险就杀进程”，而是按风险等级分级响应。`RiskResponsePolicy` 把
native 风险评分（score + 高置信信号数）映射成五档动作：

- `ALLOW`：无风险信号。
- `MONITOR`：低风险，仅记录，继续运行。
- `CHALLENGE`：中风险，继续运行；敏感操作（登录/支付/授权激活）应走服务端二次校验。
- `RESTRICT`：高风险，继续运行；高价值功能应被限制或隐藏。
- `TERMINATE`：阻断/杀进程。

**关键商业保证：`TERMINATE` 仅在 `strict` profile 或 `commercial-mode` 下可达。**
`balanced`/`compat` 即使在 `block` 策略下，最高也只到 `RESTRICT`，不会杀真实用户。
要让壳真的阻断进程，必须显式选择 `--risk-policy block --risk-profile strict`（或
`--commercial-mode`）。

各 `--risk-policy` 的动作上限：

| policy | 最高动作 |
| --- | --- |
| off | ALLOW |
| log | MONITOR |
| warn | CHALLENGE |
| degrade | RESTRICT |
| block | TERMINATE（仍受 strict/commercial 闸门限制） |

宿主 App 通过公开 API `com.enko.shell.EnkoRuntime` 查询当前风险等级并自行决定降级方式：

```java
if (com.enko.shell.EnkoRuntime.shouldRestrict()) {
    // 隐藏/禁用高价值功能
} else if (com.enko.shell.EnkoRuntime.shouldChallenge()) {
    // 登录/支付前要求服务端二次校验
}
```

该 API 是只读遥测，不替代服务端校验：授权、支付、会员、资产等高价值决策仍须服务端确认，
风险等级只作为其中一个信号（参见 P6-2）。

## 运行时反 dump（DEX 内存保护）

加载 payload 后，壳对内存中的 DEX DirectByteBuffer 做三层处理：

1. `corruptDexHeaders`：始终执行，随机覆盖每个 buffer 前 256 字节（ART 已内化结构，仅干扰内存扫描 dump）。
2. **二选一**，互斥避免相互竞争：
   - `protectDexPages=true`（默认）：`scheduleDexProtect` 等 `sAppCreateDone` 后 `mprotect(PROT_NONE)` 封存 DEX 页。
   - `protectDexPages=false`：`scheduleBufferWipe` 改用**主动监控**——等 `sAppCreateDone`（最长 30s 兜底）+ GC 后再整块擦除源 buffer，不再用固定延迟。
3. `clearDexFileCookies`：仅在 `commercialMode` 或 `strict+block` 下执行，置空 `DexFile.mCookie` 阻断反射 dump。

**重要兼容性约束**：当按需抽取启用（`extractEnabled && extractOnDemand`）时，payload 类加载器仍在
惰性加载类、需要源 buffer 与 cookie，因此此时**自动跳过** buffer 擦除和 cookie 清理，避免破坏业务。
`clearDexFileCookies` 默认关闭，因为部分 Android 版本 ART 会因此 crash，只在强保护档显式开启。

## 方法保护排查

正确 flag 或关键业务流程卡住时，优先排查方法选择：

1. 用兼容推荐模板重新加固，确认业务逻辑不被破坏。
2. 查看 `report.json` 的 `method_protection.map`，确认热路径、UI 生命周期、反射/JNI/monitor 方法是否被降级。
3. 降低 DEX2C 数量，把小方法、高频回调和复杂异常流留给 extract 或轻 VMP。
4. 使用语义 smoke 工具采集 ANR、logcat、阶段耗时。

## Web 任务系统

Web 新建任务后会进入后台执行，前端断开不影响构建。开发服务没有 WebSocket 时会自动使用轮询。

任务状态写入：

```text
web-console/.job-cache/<job-id>/job.json
```

任务详情页应重点看：

- 命令参数
- 实时/轮询日志
- 输出 APK 路径
- `report.json` 摘要
- VMP 降级原因和 DEX2C OLLVM fallback 状态

## Release Manifest

`release/release_manifest.json` 使用相对路径，避免机器绑定。重新生成：

```bash
python packer/release_manifest_tool.py build \
  --engine-manifest release/engine_manifest.json \
  --rules-file release/rules.json \
  --policy-file release/policy.json \
  --protection-map full-open-protect.txt \
  --map-version full-open.v1 \
  --presets-file release/presets.json \
  --output release/release_manifest.json
```

校验：

```bash
python packer/release_manifest_tool.py validate \
  --manifest release/release_manifest.json \
  --check-files
```

## CI 回归

GitHub Actions 默认执行：

- `unit-tests`：Python 单测和覆盖率。
- `hygiene-and-release`：仓库卫生检查与 release manifest 路径校验。
- `scenario-apk-build`：安装 Android SDK/NDK/CMake，构建全部语义场景 APK，并校验场景目录。
- `security-lint`：Bandit 扫描 packer。

真机/模拟器语义冒烟是手动任务：在 Actions 里运行 `workflow_dispatch`，把 `run_device_smoke` 设为 `true`。该任务要求自托管 runner 带 `self-hosted` 和 `android` 标签，且 `adb get-state` 返回 `device`。
