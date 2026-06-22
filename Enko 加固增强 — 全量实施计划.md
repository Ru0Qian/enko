# Enko 加固增强 — 全量实施计划
按优先级分为 5 个阶段，每阶段可独立发布。前一阶段完成后再开始下一阶段。
# Phase 1 — 快速修补（1-2 天）
修复已有代码中的遗漏和低成本高收益项。
## 1.1 启用 scheduleBufferWipe
**问题**: `ProxyApplication.scheduleBufferWipe()` 已实现但从未调用。DEX buffer 在 `corruptDexHeaders` 后仅改了 8 字节 magic，剩余内容完整可读。
**修改**: `ProxyApplication.java` — 在 `corruptDexHeaders(dexBuffers)` 之后立即调用 `scheduleBufferWipe(dexBuffers)`。
**注意**: 当前注释说 ART JIT 可能还在访问 buffer，5 秒延迟可能不够。建议改为 10 秒，并在 wipe 前调用 `System.gc()` 提示 JIT 完成编译。
## 1.2
**问题**: `check_frida_maps()` 只查 `/proc/self/maps` 中的 `frida-agent/gadget/inject`，改名即绕过。
**修改**: `enko_anti_debug.c` 新增 `check_frida_threads()`：
* 遍历 `/proc/self/task/*/comm`
* 匹配特征线程名: `gmain`, `gdbus`, `gum-js-loop`, `frida-helper`, `linjector`
* 在 `watchdog_thread` 和 `enko_native_detect_risk` 中调用
## 1.4 补充 Frida 检测：内存特征扫描
**修改**: `enko_anti_debug.c` 新增 `check_frida_memory_pattern()`：
* 读取 `/proc/self/maps` 中 `r-xp` 段的可执行匿名映射
* 在映射内搜索字节特征: `"LIBFRIDA"`, `"frida-agent"`, `gum_interceptor` 等
* 注意: 只读少量页面（前 4KB），避免性能问题
## 1.5 补充 Frida 检测：随机端口探测
**修改**: `RiskDetector.java` 中 `hasFridaServer()` 增加：
* 扫描 `/proc/net/tcp` 和 `/proc/net/tcp6`
* 查找处于 LISTEN 状态的 socket
* 对每个 LISTEN 端口尝试发送 D-Bus `AUTH` 握手 (`"\x00"` + `"AUTH\r\n"`)
* Frida 会响应 `REJECTED` — 这是 Frida 专有特征
# Phase 2 — Native SO 保护（3-5 天）
当前 `.so` 是明文编译产物，IDA/Ghidra 可直接分析全部逻辑。
## 2.1 Native 字符串加密
**问题**: `enko_key.c` 中 `PAYLOAD_KEY_SEED = "enko_payload_key_v1"` 明文可见，`enko_gcm.c` 中 magic `"ENKO_PAYLOAD_V1"` 明文可见。
**方案**: 编译期字符串混淆。
* 新建 `enko_obfstr.h` — 宏或 constexpr 函数，编译期 XOR 加密，运行时解密
* 对所有安全敏感字符串使用: PAYLOAD_KEY_SEED, MASK_PART_A..D, MAGIC, 日志 TAG 等
* 实现方式: C11 `_Generic` 宏 + 编译期计算，无需 C++
```c
// enko_obfstr.h 示例
#define OBFSTR_KEY 0xC7
#define OBFSTR_DECL(name, ...) \
    static const uint8_t name##_enc[] = { __VA_ARGS__ }; \
    static inline void name##_dec(char *out, size_t len) { \
        for (size_t i = 0; i < len; i++) out[i] = name##_enc[i] ^ OBFSTR_KEY; \
        out[len] = '\0'; \
    }
```
* packer 中新增 `tools/gen_obfstr.py` 辅助脚本，输入明文字符串输出 XOR 加密后的 C 数组
## 2.2 OLLVM / 混淆编译
**问题**: 函数逻辑完全可逆。
**方案**: 集成 OLLVM 或 Hikari 分支到 NDK 构建。
* `CMakeLists.txt` 新增编译选项（仅在使用 obfuscating compiler 时启用）:
    * `-mllvm -fla` (控制流平坦化)
    * `-mllvm -sub` (指令替换)
    * `-mllvm -bcf` (虚假控制流)
* 优先混淆文件: `enko_key.c`, `enko_gcm.c`, `enko_integrity.c`, `enko_anti_debug.c`
* 性能敏感文件（`enko_aes.c`）可只开 `-sub`
* 记录到 `README.md` 中说明如何获取和配置 OLLVM toolchain
**替代方案**: 如不愿维护 OLLVM toolchain，可使用 `obfuscator-llvm` Docker 镜像，CI 中交叉编译。
## 2.3 Native 层 anti-hook 检测
**问题**: 攻击者可 inline hook `nativeDetectRisk` 等 JNI 函数，直接返回 0。
**方案**: `enko_anti_debug.c` 新增 `check_inline_hooks()`：
* 获取关键函数（`enko_native_detect_risk`, `enko_derive_payload_key`, `enko_gcm_decrypt`）的入口地址
* 检查前 16 字节是否包含跳转指令模式:
    * ARM64: `BR X16/X17` (0xD61F0200/0xD61F0220), `LDR Xn, [PC, #offset]`
    * ARM32: `LDR PC, [PC, #-4]`
    * x86: `JMP [addr]` (0xFF 0x25), `JMP rel32` (0xE9)
* 检测到则设 risk flag bit 3
* 在 `JNI_OnLoad` 和 watchdog 中定期检查
## 2.4 .init_array 增强
**问题**: `enko_preinit()` 当前为空。
**修改**: `enko_jni.c` 中 `enko_preinit()` 添加:
* 读取 `/proc/self/maps` 检查是否有已加载的 frida/xposed 相关 so
* 如检测到，直接 `_exit(1)`
* 这是 **最早可执行代码**，在 JNI_OnLoad 之前
# Phase 3 — 密钥架构重构（3-5 天）
## 3.1 Per-APK 随机密钥
**问题**: 当前所有加固 APK 共享同一 payload key（由编译期常量确定性派生）。逆向一个 APK 即可解密所有。
**方案**:
* packer 为每个 APK 生成 32 字节随机 key
* 将随机 key XOR 加密后嵌入 `.so` 的 `.rodata` 段的一个占位区
* 具体流程:
    1. shell-app 编译时，`enko_key.c` 中预留 32 字节占位 `PAYLOAD_KEY_SLOT = {0x00...}` + 32 字节校验 `PAYLOAD_KEY_CHECK = {0x00...}`
    2. packer 生成随机 key K
    3. packer 对每个 ABI 的 `libenko.so` 进行二进制 patch:
        * 在 `.rodata` 中找到 `PAYLOAD_KEY_SLOT` 占位符（前后有 magic marker）
        * 写入 `K XOR NATIVE_KEY_XOR_MASK`
        * 写入 `SHA-256(K)[:32]` 到 CHECK 区域
    4. native 运行时: `build_mask()` XOR `PAYLOAD_KEY_SLOT` → 得到 K，验证 CHECK
* **兼容性**: 保留 `derive_embedded_payload_key()` 作为 fallback，新增 `derive_per_apk_key()` 优先尝试
* packer 新增 `--per-apk-key` flag（默认开启）
## 3.2 Config 加密（替代 HMAC 明文）
**问题**: runtime config 当前是 base64 明文 + HMAC，攻击者可读取配置内容（如 realApplicationClass）。
**方案**:
* 将 config 整体 AES-GCM 加密（key 从 native 派生），替代当前的 base64 + HMAC
* `NativeBridge.nativeDecryptConfig()` 已有 JNI 实现但未使用
* 流程:
    1. packer: 用 `derive_cfg_key()` 加密整个 config body → `ENKO_CFG_ENC_V1` + nonce + ciphertext + tag
    2. runtime: `NativeBridge.nativeDecryptConfig(encrypted)` → 得到明文 config
* 修改 `ProxyApplication.installPayload()` 中 config 读取流程
* 移除 `verifyConfigIntegrity()` 和 `compute_config_hmac()`（AES-GCM 自带认证）
# Phase 4 — 函数级指令抽取 + DEX2C（7-10 天）
核心目标：将 Dalvik 字节码从 DEX 中移除，转为 native 代码执行，使反编译工具（jadx/JEB）无法还原业务逻辑。
## 4.1 函数级指令抽取（Method Body Extraction）
**问题**: 当前 DEX 整体加密在运行时解密后，所有方法字节码仍完整驻留在内存中，可被 dump 后直接反编译。
**方案**: 保留 DEX 结构但抽空指定方法的 `insns`（指令体），运行时按需回填。
* packer 阶段:
    1. 解析 DEX，遍历指定类/方法的 `code_item`
    2. 提取 `insns` 字节码，存入独立加密文件 `libenko_extract.dat`（AES-GCM，key 复用 per-APK key）
    3. 将 DEX 中对应 `code_item.insns` 填充为 `nop`（`0x0000`）或替换为 `throw` 桩
    4. 记录方法索引 → 偏移映射表（加密存储）
* runtime 阶段:
    1. native 层 hook ART `ClassLinker::DefineClass` 或 `ClassLinker::LoadMethod`
    2. 当目标方法首次加载时，从加密文件解密对应 `insns`，写回内存中的 `CodeItem`
    3. 回填完成后立即擦除解密 buffer
* 实现要点:
    * 需适配 ART 版本差异（Android 8-15 的 `CodeItem` 布局不同）
    * hook 方式优先用 PLT hook（稳定），fallback inline hook
    * packer 新增 `--extract-methods` 参数，支持类名/方法名通配符
    * 新增 `enko_extract.c` 实现 native 端回填逻辑
## 4.2 DEX2C 编译（Dalvik → Native）
**问题**: 指令抽取仍然是 Dalvik 字节码，dump 内存仍可恢复。DEX2C 将字节码彻底编译为 C 代码，消除字节码形态。
**方案**: 在 packer 中实现 Dalvik → C 翻译器。
* packer 阶段:
    1. 解析目标方法的 Dalvik 字节码
    2. 翻译为等价 C 函数（每条 Dalvik 指令 → 对应 C 语句）
    3. 生成的 C 代码通过 NDK 编译为 `.so`（`libenko_dex2c.so`）
    4. 原 DEX 中被保护的方法标记为 `ACC_NATIVE`，注册到生成的 JNI 函数
* 翻译器需处理的核心指令:
    * 算术/逻辑: `add-int`, `mul-long`, `and-int` 等 → 直接 C 运算符
    * 对象操作: `new-instance`, `iget/iput`, `invoke-*` → JNI 调用（`NewObject`, `GetIntField`, `CallVoidMethod` 等）
    * 数组操作: `aget/aput`, `array-length` → JNI 数组 API
    * 控制流: `if-*`, `goto`, `switch` → C 的 `if/goto/switch`
    * 异常: `throw`, `try-catch` → `ExceptionCheck()` + `goto` 模拟
* 生成代码的保护:
    * 生成的 C 代码自动受 Phase 2 的 OLLVM 混淆保护
    * 函数名随机化（`enko_d2c_XXXX`），不暴露原始类/方法名
    * JNI 注册使用 `RegisterNatives` 动态注册，不走静态命名
* packer 新增 `--dex2c-methods` 参数，支持类名/方法名通配符
* 新增 `packer/dex2c/` 目录，含翻译器核心逻辑
## 4.3 混合模式策略
**说明**: 4.1 和 4.2 可组合使用，packer 按配置决定每个方法的保护级别：
* **level 0** — 无保护（保留原始字节码）
* **level 1** — 指令抽取（运行时回填，性能开销低，兼容性好）
* **level 2** — VMP（已有能力，自定义解释器执行）
* **level 3** — DEX2C（最高安全性，性能最优但包体增大）
* packer 新增 `--protection-map` 配置文件，按类/方法指定保护级别
* 默认策略: 关键业务方法 level 3，普通方法 level 1，性能热点 level 0
# Phase 5 — 反 dump 增强（2-3 天）
## 5.1 延迟擦除改为主动监控
**问题**: `scheduleBufferWipe` 使用固定 5 秒延迟，不可靠。
**方案**: 改为 **ClassLoader 监控线程**:
* 新线程循环调用 `Runtime.getRuntime().gc()`
* 等待 `ClassLoader` 首次成功加载一个 payload 类（表示 DEX 已被 ART 完全处理）
* 此时立即 wipe 所有 DEX buffer
* fallback: 最长等待 30 秒后强制 wipe
## 5.2 /proc/self/mem 写保护
**修改**: `enko_anti_dump.c` — DEX buffer 加载完成后:
* `mprotect(dex_region, len, PROT_NONE)` 将 DEX 内存设为不可读不可写
* 这样即使 `/proc/self/mem` 被读取，也会得到全零或 SIGBUS
* 注意: ART JIT 可能还需要访问，需在 JIT 完成后执行（与 5.1 配合）
## 5.3 DEX cookie 清理
**问题**: `DexFile` 内部持有的 cookie 可被反射获取，用于 dump DEX 原始内容。
**方案**: 通过反射或 JNI:
* 获取 `DexPathList.dexElements[].dexFile` 中的 `mCookie` 字段
* 在 DEX 加载完成后将 `mCookie` 置零或置为 invalid 值
* 这会导致后续的 `DexFile.loadClass` 失败，但此时所有类已被加载
* 注意: 部分 Android 版本的 ART 可能 crash，需按版本条件执行
# Phase 6 — 高级防护（5-7 天）
## 6.1 Shell DEX 自身混淆
**问题**: shell 的 Java 代码经 ProGuard 混淆，但控制流仍可分析。
**方案**:
* 对 `ProxyApplication` 关键方法启用 VMP 保护（用项目自身的 DEX VMP）
* 在 `packer/harden_apk.py` 构建流程中，先对 shell DEX 的关键方法执行 VMP 编译
* 目标方法: `installPayload`, `enforceIdentity`, `verifyShellDexIntegrity`, `verifyNativeLibsIntegrity`
* 需要额外处理: shell DEX 的 VMP blob 需要不同的存储路径（与 payload VMP 区分）
## 6.2 多态壳（Polymorphic Shell）
**问题**: 所有加固 APK 使用同一 shell DEX，攻击者逆向一次即可复用。
**方案**:
* packer 在注入 shell DEX 前对其进行随机变换:
    * 随机重命名类/方法/字段（需同步更新 AndroidManifest、proguard mapping、JNI 注册名）
    * 插入随机垃圾方法和死代码
    * 随机化字符串常量（加密后运行时解密）
    * 随机化方法调用顺序（在安全检查链中插入虚假检查）
* 每次加固生成唯一的 shell，使通用脱壳脚本失效
* 实现复杂度高，建议最后做
## 6.3 Java 层 anti-hook
**方案**: `ProxyApplication` 启动时检测 Java 方法 hook:
* 反射获取关键方法的 `ArtMethod` 入口点（通过 `Method.getArtMethod()` 或已知偏移）
* 检查入口点是否指向 `.so` 中已知的 trampoline 区域
* 检测 `Thread.getAllStackTraces()` 中是否有 Xposed/Frida 相关栈帧
* 使用 `Runtime.getRuntime().exec("cat /proc/self/maps")` 作为独立进程读取 maps（绕过 maps hook）
# 实施优先级总结
1. **Phase 1** (1.1-1.5): 快速提升，修复明显遗漏
2. **Phase 2** (2.1-2.4): native 保护是当前最大短板
3. **Phase 3** (3.1-3.2): 解决 "一破全破" 的密钥问题
4. **Phase 4** (4.1-4.3): 函数级指令抽取 + DEX2C，核心字节码从 DEX 中彻底消失
5. **Phase 5** (5.1-5.3): 反 dump 增强（Phase 4 完成后压力大幅降低）
6. **Phase 6** (6.1-6.3): 进阶防护，对标商业方案
