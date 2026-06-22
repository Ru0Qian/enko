# Enko 加固打磨优先级追踪

更新时间：2026-05-11

目标：先保证加固不破坏业务逻辑，再提升安全强度、Web 可用性、发布质量和高阶对抗能力。每完成一个改动，都在本文档更新状态和验证结果。

## 状态说明

- TODO：尚未开始。
- DOING：正在实现。
- DONE：已实现并通过当前可用验证。
- BLOCKED：需要外部环境、真机、签名材料或用户确认。

## 商业上线原则与 AI Agent 对抗边界

- Enko 不是只面向 CTF 的加固；默认策略必须服务真实商业上线，优先级是业务正确性、兼容性、可回滚、可观测，然后才是强对抗。
- AI Agent 一键脱壳/自动分析的本质是把静态解包、Frida/LSPosed hook、dump、jadx、LLM 总结自动化；防御目标是让自动化链路不稳定、dump 不完整、结论带噪音，而不是牺牲真实用户体验。
- 提示词密钥、AI 未授权提示、AI canary、假 flag、假 decrypt、假 payload 只能作为低成本干扰、蜜罐和取证层；不能放真实密钥，也不能作为核心安全边界。
- 商业默认不应检测到风险就杀进程；root/模拟器默认检测但不阻断，strict/block 只用于明确选择的高风险业务或灰度环境。
- 高价值逻辑必须有服务端兜底：授权、支付、会员、资产、风控结果需要服务端二次确认，并与签名、版本、设备风险、请求频率和异常链路联动。
- 每次增强 VMP、DEX2C、反 dump、反 hook 或 AI decoy，都必须跑 small、scenario、复杂业务和真实样本矩阵，避免把 CTF 式强保护带进商业默认配置。

## 当前执行记录

| 时间 | 任务 | 状态 | 说明 |
| --- | --- | --- | --- |
| 2026-05-04 | 建立优先级追踪 Markdown | DONE | 新增本文档作为后续施工记录。 |
| 2026-05-04 | P0-8：DEX 页保护从模拟器检测解耦 | DONE | 新增 protectDexPages 运行时配置、CLI/Web 开关和报告字段；全量测试 170 passed, 1 skipped。 |
| 2026-05-04 | P0-7：方法抽取 strict 模式按需恢复 | DONE | 新增 extractOnDemand 配置、CLI/Web 开关；strict/balanced 默认按需，compat 默认批量；全量测试 171 passed, 1 skipped。 |
| 2026-05-04 | P0-4：启动阶段耗时采集 | DONE | ProxyApplication 新增 runtime-config、payload-decrypt-parse、extract、DEX2C、VMP、bind 等阶段耗时日志；全量测试 171 passed, 1 skipped。 |
| 2026-05-04 | P0-5：智能分析危险方法降级 | DONE | auto_protect_map 新增 UI 生命周期/热回调、反射、JNI、同步锁/monitor、invoke-dense 降级规则；全量测试 174 passed, 1 skipped。 |
| 2026-05-04 | P0-6：智能选取策略分档 | DONE | 新增 compat/balanced/strong/extreme 四档 auto-protect profile，接入 packer CLI、Web UI 和报告；全量测试 176 passed, 1 skipped。 |
| 2026-05-05 | P0-2：语义 smoke 诊断采集 | DONE | android_semantic_smoke 新增阶段耗时、成功后 ANR/crash 扫描、logcat/UI/dumpsys 诊断目录；全量测试 179 passed, 1 skipped。 |
| 2026-05-05 | P0-1：统一 APK 测试目录 | DONE | 新增 run_semantic_catalog，覆盖 small、5 个 scenario raw/hardened、复杂业务和真实业务样本元数据；catalog-summary.json 已生成；全量测试 182 passed, 1 skipped。 |
| 2026-05-05 | P0-4：smoke 诊断汇总 | DONE | 新增 summarize_smoke_diagnostics，汇总 smoke-result、ProxyApplication timing、ANR/crash/跳帧信号，输出 JSON/Markdown；全量测试 186 passed, 1 skipped。 |
| 2026-05-05 | P0-9/P0-10：外部原证书签名默认流程 | DONE | harden_apk 默认输出 unsigned/aligned，新增 --sign 才执行流水线内签名；Web/测试矩阵显式传递签名意图；证书 SHA-256 可由 keystore 或输入 APK 提取；全量测试 189 passed, 1 skipped。 |
| 2026-05-05 | P1-4：小方法/高频方法性能降级 | DONE | auto_protect_map 新增 tiny-runtime-method 和 performance-hot-risk 规则，小 boolean/getter 与 run/call/invoke/worker 等高频入口默认避开 DEX2C；全量测试 191 passed, 1 skipped。 |
| 2026-05-05 | P1-8：保护地图进入安全报告 | DONE | security report 新增 method_protection.map，记录请求目标、VMP/Shell VMP 实际编译目标、DEX2C 目标库和 auto-protect 分数原因；全量测试 192 passed, 1 skipped。 |
| 2026-05-05 | P1-3：OLLVM 路径和版本检测前置 | DONE | harden_apk 新增 DEX2C OLLVM clang preflight，报告 ollvm_available/version/status/reason；required/commercial 缺失时编译前失败，best-effort 明确记录降级原因；全量测试 195 passed, 1 skipped。 |
| 2026-05-05 | P1-2：DEX2C OLLVM 默认开启与实际保护报告 | DONE | DEX2C 编译器回传 per-ABI 构建模式，security report 明确列出 ollvm_protected_libraries、fallback_libraries、ollvm_effective 和 fallback_used；全量测试 195 passed, 1 skipped。 |
| 2026-05-05 | P1-1：VMP light 混淆失败自动降级 | DONE | VMP DEX 编译失败时会从 light/custom 混淆重试 stable 参数，并在 report 中记录 effective_*、downgraded 和 downgrade_reason；全量测试 196 passed, 1 skipped。 |
| 2026-05-05 | P1-5：VMP 字符串池和标识符明文审计加强 | DONE | 确认 VMP blob v4 已加密字符串池；security report 补充 string_pool_format/decryption_mode，并在 commercial/strict+block 下要求类名/方法名/签名明文审计 clean；全量测试 196 passed, 1 skipped。 |
| 2026-05-05 | P1-6：payload envelope 随机 padding | DONE | payload 已有 per-build seed XOR envelope 隐藏稳定 AES magic；新增 8-95 字节随机尾部 padding，native unwrap 改为按声明 inner_len 解包并忽略 padding，报告记录 envelope metadata；全量测试 198 passed, 1 skipped。 |
| 2026-05-05 | P1-7：壳字段名多态化 | DONE | polymorphic shell 从类名/方法名扩展到高信号字段名，同长度替换并继续校验 DEX string_ids 排序；报告新增 field_alias_count；全量测试 199 passed, 1 skipped。 |
| 2026-05-05 | P3-1/P3-2/P3-3：Web 任务列表、后台任务和详情页打磨 | DONE | dev/prod 任务新增 job.json 快照落盘、重启恢复和删除同步；开发服务无 WebSocket 时默认轮询，不再误报断开；任务详情显示命令参数、产物状态和真实 report.json 摘要；全量测试 201 passed, 1 skipped。 |
| 2026-05-05 | P3-4：Web UI 同步底层能力矩阵 | DONE | 新建任务摘要区新增能力同步矩阵，直观看到方法抽取、VMP、壳 VMP、DEX2C OLLVM、多态壳、DEX 页封存、签名策略和发布门禁状态；JS 语法检查通过；全量测试 202 passed, 1 skipped。 |
| 2026-05-05 | P3-5：兼容推荐/强保护一键模板 | DONE | 配置方案区新增兼容推荐和强保护快捷按钮；兼容模板降低 DEX2C 风险并关闭 root/模拟器阻断，强保护模板启用 Shell VMP、多态壳、DEX2C OLLVM required 和 strict/block；全量测试 203 passed, 1 skipped。 |
| 2026-05-05 | P3-6：上传后自动静态分析并生成推荐保护图 | DONE | APK 上传成功后自动运行方法分析，并静默保存推荐 protection map；用户仍可在推荐/高级面板二次调整；全量测试 204 passed, 1 skipped。 |
| 2026-05-05 | P4-1：项目卫生清理工具增强 | DONE | clean_workspace.py 保持 dry-run 默认和 output 显式选择边界，新增 --json 清理计划输出；已 dry-run 盘点 output 94 项约 60.4MB，未删除文件；全量测试 206 passed, 1 skipped。 |
| 2026-05-05 | P4-2：敏感/大文件入库检查 | DONE | 新增 check_repo_hygiene.py，校验 .gitignore 必须覆盖 jks/APK/idsig/output/Gradle/apktool；Git 仓库中会额外检查禁止跟踪文件；当前非 Git 工作树下检查 ok；全量测试 209 passed, 1 skipped。 |
| 2026-05-05 | P4-3：Release Manifest 相对路径化 | DONE | release_manifest_tool 默认写入相对路径，新增 --absolute-paths 兼容开关；release/release_manifest.json 已重建为 portable path 并通过 --check-files；全量测试 211 passed, 1 skipped。 |
| 2026-05-05 | P4-4：运维文档补齐 | DONE | 新增 docs/OPERATIONS.md，覆盖签名策略、OLLVM 配置、保护档位、方法保护排查、Web 任务和 release manifest；全量测试 211 passed, 1 skipped。 |
| 2026-05-05 | P4-5：CI 回归矩阵 | DONE | GitHub Actions 新增 hygiene/release 校验、场景 APK 构建和 workflow_dispatch 自托管设备冒烟入口；本地场景 assemble PASS；全量测试 213 passed, 1 skipped。 |
| 2026-05-05 | P3-7：Web 前端拆分 | DONE | app.js 拆出 js/jobs.js 和 js/report.js，任务/报告渲染独立维护；浏览器打开任务/报告页无 JS error；全量测试 214 passed, 1 skipped。 |
| 2026-05-05 | P2-7：VMP 语义重点回归 | DONE | 新增 monitor、packed/sparse switch、fill-array payload、try/catch 地址翻译回归；修复 payload 数据被误解码为普通指令的问题；全量测试 219 passed, 1 skipped。 |
| 2026-05-05 | P2-6：热点/高风险方法降级剩余项 | DONE | 智能方法选择新增 switch、try/catch、fill-array-data、monitor 结构风险识别，默认把这些方法从 VMP/DEX2C 重保护降级到 extract；全量测试 222 passed, 1 skipped。 |
| 2026-05-05 | P2-0：VMP 指令格式能力审计 | DONE | security report 和 Web 报告新增 vmp_bytecode_format，明确当前 blob v4/fixed8/字段未随机/未支持可变长，避免把 P2-1/P2-2 误判为已完成能力；全量测试 222 passed, 1 skipped。 |
| 2026-05-05 | P5-0：现代 Hook 注入链检测扩展 | DONE | Native/Java 检测补齐 LSPosed/Riru/Zygisk/LSPatch、Dobby/Whale、KernelSU/APatch 等关键词，并集中 native hook/root 关键词判断；全量测试 223 passed, 1 skipped。 |
| 2026-05-05 | P2-3a：VMP add-int 语义别名 handler | DONE | 编译器开始对 add-int/add-int-literal 使用安全 alias opcode，native computed-goto 为 18 个 add 语义别名提供独立 label，fallback switch 同步支持；Gradle/NDK assembleDebug PASS；全量测试 225 passed, 1 skipped。 |
| 2026-05-05 | P0-1/P0-3：设备语义 catalog runner 稳定性 | DONE | ADB 设备恢复后修复 catalog runner：单项超时不再中断全局矩阵，每个场景结束后 force-stop 包名隔离状态污染；设备 r2 结果显示 5 个 raw 场景和 5 个 hardened 场景均 PASS，旧 small hardened current/root 产物仍 FAIL；全量测试 227 passed, 1 skipped。 |
| 2026-05-05 | P0-3：small flag 破坏复测与产物刷新 | DONE | 用当前 shell/packer fresh 构建 small stable/light；两者均在模拟器通过正确 flag 语义 smoke，light 已提升为 app-hardened-current.apk 和 test_apks/small_hardened.apk；small catalog raw/current/root 三项全部 PASS。 |
| 2026-05-05 | P0-2：small 回归脚本 logcat fallback 修正 | DONE | run_small_semantic_regression 补齐 small 专用 package/activity/flag/expect-log/log-tag、post-success health check 和诊断目录，避免 UIAutomator 不可用时误报失败；聚焦测试 6 passed。 |
| 2026-05-05 | P0-1：完整设备语义 catalog r3 | DONE | 重新跑全量设备 catalog：small raw/current/root、5 个 scenario raw、5 个 scenario hardened 全部 PASS；summary 位于 output/semantic-device-20260505-r3/catalog-summary.json；真实业务样本仍 metadata-only。 |
| 2026-05-05 | P2-3b：VMP add-int alias 多形态实现 | DONE | add-int/add-int-literal 的 18 个 alias label 从同一宏展开改为 8 种等价 native 实现形态；report 新增 semantic_alias_implementation=native-multi-shape-add-v1；Gradle/NDK assembleDebug PASS，fresh small light 与 current/root small catalog PASS，全量测试 228 passed, 1 skipped。 |
| 2026-05-05 | P2-3c：VMP 低风险 int 语义 alias 扩展 | DONE | 编译器为 sub/and/or/xor 及其 2addr/lit16/lit8 形态启用安全 alias 池；native computed-goto 增加 sub/and/or/xor 独立多形态 handler，fallback switch 同步；small current/root 语义 PASS，全量测试 228 passed, 1 skipped。 |
| 2026-05-05 | P2-5：VMP 解释器核心分区首版 | DONE | 新增 compat/light/strong VM tier 配置、CLI/Web 控制、运行时 cfg、JNI 设置入口和 native 上下文状态；auto 会按 profile/risk 选择档位；报告与 Web 详情展示 vmp_interpreter_core；Gradle/NDK assembleDebug PASS，全量测试 228 passed, 1 skipped。 |
| 2026-05-11 | 商业上线与 AI Agent 防御计划补充 | DONE | 明确 Enko 默认按商业生产级而非 CTF 极限对抗推进；新增 AI canary/decoy、自动脱壳回归实验室、服务端风控、灰度回滚和商业默认策略任务。 |
| 2026-06-01 | 安全审查批次一：config.env 密钥、VMP try/catch、注释失真 | DONE | 删除含真值的 deploy/config.env 改为 .example，.gitignore + check_repo_hygiene 增加 *.env/deploy/config.env 守卫；VMP 编译期标记含 try/catch 方法，commercial/strict+block 下 fail-closed，report 暴露 has_try_catch；修正 NativeBridge/proguard 注释；全量测试 229 passed, 1 skipped。 |
| 2026-06-01 | P6-0/P6-1：风险分级响应矩阵 | DONE | 新增 RiskResponsePolicy（5 档动作，TERMINATE 仅 strict/commercial 可达）+ RiskState + 公开 API EnkoRuntime；ProxyApplication/NetworkRiskWatchdog 接入；默认 balanced 封顶 RESTRICT 实现商业默认不误杀；新增 javac 行为矩阵测试；OPERATIONS 文档补章节；全量测试 233 passed, 1 skipped。 |
| 2026-06-01 | P6-5：Web UI 商业上线提示 | DONE | 5 个风险策略按钮加 hover tooltip 区分商业/兼容/调试场景；Root/模拟器/DEX 页封存/代理-VPN 四开关加 ⚠ 兼容性警告；策略组顶部加「默认分级响应」徽章 + 底部商业 vs 强对抗速查；app.js summaryPolicy 显示「可终止/不杀进程」标签并变色；能力矩阵新增「风险响应」行；node --check 通过，HTML 标签平衡，全量 233 passed。 |
| 2026-06-01 | 1.3：反 dump 死代码接入 | DONE | scheduleBufferWipe 改主动监控（等 sAppCreateDone+GC，30s 兜底）；installPayload 接入 protectDexPages 开→封存页/关→擦 buffer 互斥；clearDexFileCookies 仅 commercial/strict+block；按需抽取时自动跳过避免破坏惰性加载；shell Java 包对 android-36 编译 exit 0，全量 233 passed。 |
| 2026-06-01 | 1.4：删除未用模块层 | DONE | 确认 constants.py/apk_decoder.py/polymorphic_shell.py 无任何流水线/测试导入且内容漂移过期；删除三文件并清理 deploy.py/update.bat 引用；harden_apk 为唯一权威实现；全量 233 passed。 |
| 2026-06-22 | P5-7/P5-2：反 AI 全自动逆向 | DONE | 新增 `packer/ai_decoy.py` + `--ai-decoy` CLI(商业模式自动启用):per-build canary token + 假 AES key + 假 license flag + 假 API endpoints,写到 assets/;报告记录 canary 用于溯源。新增 `tools/dump_resistance_check.py` + 11 个离线单测:**模拟器真机 5/5 PASS** —— 验证 DEX 页封存(2/2)、/proc/mem 读拒绝、loose DEX 不暴露、canary 可追溯。同时联动验证 1.3 mprotect 真实生效、P6-1 分级响应在 emulator 不误杀(compat 档系统完整性异常仅记录),per-APK key 真实运行。全量 249 passed, 1 skipped。 |

## P0：必须先做

| ID | 事项 | 状态 | 目的 |
| --- | --- | --- | --- |
| P0-1 | 建立完整测试矩阵：small APK、三个场景 APK、复杂业务 APK、真实业务 APK 样本 | DONE | 统一 catalog 已覆盖 small、5 个 scenario raw/hardened、复杂业务；真实业务样本因缺少 package/activity/业务成功条件，暂作为 metadata-only。 |
| P0-2 | 每个测试 APK 配套自动触发脚本：启动、点击、输入 flag、触发复杂业务流程 | DONE | smoke 工具已支持 flag 输入、复杂业务 trigger、成功后健康检查与诊断采集。 |
| P0-3 | 修复正确 flag 后卡死、变慢问题 | DONE | 当前已验证：fresh small stable/light 均 PASS；app-hardened-current.apk 和 test_apks/small_hardened.apk 已刷新为当前 light 产物；small catalog raw/current/root 三项 PASS；scenario matrix raw/hardened 复杂业务在 r2 设备测试中 PASS。真实业务样本仍需补 package/activity/业务成功条件后才能纳入语义验证。 |
| P0-4 | 加入 ANR、卡顿、启动耗时、点击响应耗时采集 | DONE | 启动阶段耗时、smoke 阶段耗时、成功后健康检查、诊断采集和统一汇总已完成。 |
| P0-5 | 方法保护智能分析升级：识别 UI 生命周期、热路径、反射、JNI、异常流、同步锁、复杂控制流 | DONE | 第一版已完成：危险方法自动降级，避免优先进入 VMP/DEX2C。 |
| P0-6 | 智能选取策略分档：兼容优先、平衡、强保护、极限保护 | DONE | 已接入 --auto-protect-profile 和 Web 智能选择下拉。 |
| P0-7 | 方法抽取 strict 模式改为按需恢复，compat 模式保留批量恢复 | DONE | 已接入 extractOnDemand；strict/balanced 默认按需，compat 默认批量。 |
| P0-8 | DEX 内存页保护从模拟器检测中解耦，独立成 protectDexPages/sealDexAfterLoad | DONE | 已接入 protectDexPages，默认开启，可通过 --no-protect-dex-pages 关闭。 |
| P0-9 | 外部签名流程固定：默认输出未签名 APK，用户用原签名再签 | DONE | packer 默认 unsigned/aligned；内部签名必须显式 --sign；Web 默认 external signing。 |
| P0-10 | 启用签名校验时允许用户填写原证书 SHA-256 | DONE | --sign-cert-sha256 已支持；未内部签名时也可从完整 keystore 参数提取证书 pin，或从输入 APK 自动提取。 |

## P1：高价值安全增强

| ID | 事项 | 状态 | 目的 |
| --- | --- | --- | --- |
| P1-1 | VMP 默认 light 混淆保留，并增加失败自动降级 | DONE | payload/shell VMP 编译遇到混淆失败会自动回退 stable 参数；报告记录 requested/effective 参数和降级原因。 |
| P1-2 | DEX2C OLLVM 默认启用，并在构建报告里明确哪些 so 被 OLLVM 保护 | DONE | 默认开启已保持；报告新增 per-ABI 构建模式、OLLVM 保护路径、fallback 路径和 effective 状态。 |
| P1-3 | OLLVM 路径检测和版本检测前置 | DONE | DEX2C OLLVM clang 会在编译前执行 --version 探测，并写入 security report；required/commercial 模式下不可用会提前失败。 |
| P1-4 | libagpjnix.so 增加性能保护策略，小方法和高频方法默认不 DEX2C | DONE | 智能选取新增 tiny-runtime-method/performance-hot-risk 降级，小方法和高频回调默认偏向 extract/轻保护。 |
| P1-5 | VMP 字符串池、类名、方法名、签名描述符延迟解密继续加强 | DONE | VMP v4 字符串池已静态加密并在 native load 时解密到上下文；新增 required-clean 明文审计门禁，防止 class/method/signature 泄漏进入强保护产物。 |
| P1-6 | payload 格式增加随机 magic、随机段顺序、随机 padding | DONE | 兼容优先实现：稳定 AES magic 已被随机 seed envelope 隐藏，新增随机尾部 padding 和报告字段；DEX 段顺序保持不乱序，避免 ClassLoader 解析顺序引入兼容风险。 |
| P1-7 | 壳 Java 类名、方法名、字段名进一步多态化 | DONE | 已覆盖类名、方法名、native layer 文件名和高信号字段名；字段名同长度替换并纳入多态报告。 |
| P1-8 | release 报告输出保护地图：VMP/DEX2C/抽取/跳过原因 | DONE | 报告已输出 requested/compiled/auto_protect 明细；抽取和 DEX2C 目前记录命中数量与请求目标，VMP 记录实际编译方法。 |

## P2：VMP 深度优化

| ID | 事项 | 状态 | 目的 |
| --- | --- | --- | --- |
| P2-0 | VMP 指令格式能力审计进入 report/Web | DONE | 当前 v4 fixed8 格式、字段布局、随机化状态和 v5 目标在产物报告中显式可见。 |
| P2-1 | 固定 8 字节 VMP 指令改成可变长度编码 | TODO | 破坏静态模式识别。 |
| P2-2 | 每次构建随机指令字段布局 | TODO | 不让攻击者复用解析器。 |
| P2-3a | add-int/add-int-literal 安全语义别名 handler | DONE | 先在等价语义上启用 alias opcode 和 native 独立 label，避免碰除法、比较、字段、数组、异常等高风险语义。 |
| P2-3b | add-int/add-int-literal alias 多形态 native 实现 | DONE | 18 个 alias label 覆盖 u32 回绕、换序、wide、salt 抵消、16-bit 分段、负数减法、volatile zero、rhs 分段等 8 种实现形态。 |
| P2-3c | sub/and/or/xor 低风险 int 语义 alias 多形态实现 | DONE | 复用当前未分配的 alias opcode 子集，为 sub/and/or/xor 的普通、2addr、lit16、lit8 形态提供独立 native handler；除法、取模、移位、比较、字段、数组、异常仍保持 1:1。 |
| P2-3 | handler 多版本生成，同一语义对应多个真实实现 | DONE | 当前已覆盖 add/sub/and/or/xor 五类低风险 int 语义；剩余高风险语义不纳入本阶段，避免牺牲兼容性。 |
| P2-4 | invoke/field/array 类指令增加扰动层 | TODO | 减少 JNI 边界被直接观察的问题。 |
| P2-5 | VMP 解释器核心分区：轻量 VM、强 VM、兼容 VM | DONE | 首版已完成运行时档位分区控制面和 native 上下文状态；当前仍是兼容优先的同一解释器内策略切换，后续可继续把 strong tier 扩成更激进的 handler/扰动路径。 |
| P2-6 | 热点方法自动排除或只做轻保护 | DONE | P1-4 已覆盖小方法/高频入口；本轮补充 switch、try/catch、fill-array-data、monitor 结构风险降级，并跳过 payload 数据避免误判。 |
| P2-7 | VMP 异常处理、switch、同步块重点回归测试 | DONE | 已覆盖 monitor、packed/sparse switch、fill-array-data、try/catch；decoder 会跳过 payload 数据段，避免 switch/array payload 伪装成普通指令导致编译失败。 |

## P3：Web UI 和任务系统

| ID | 事项 | 状态 | 目的 |
| --- | --- | --- | --- |
| P3-1 | 新建任务、任务列表、任务详情彻底拆开 | DONE | 新建任务、任务列表、任务详情均为独立 view，提交后跳转详情，列表可独立进入详情。 |
| P3-2 | 加固任务改成真正后台任务，不依赖前端连接 | DONE | 后台线程执行任务，状态和日志写入 .job-cache/<job-id>/job.json；前端断开后可通过轮询恢复，服务重启会标记未完成任务为中断失败。 |
| P3-3 | 任务详情显示命令参数、日志、产物路径、失败原因、保护报告 | DONE | 详情页显示命令预览、日志、输出/报告路径、下载状态，以及真实 report.json 中的评分、VMP、DEX2C OLLVM、payload envelope、壳多态摘要。 |
| P3-4 | UI 同步全部底层能力：VMP 档位、DEX2C OLLVM、壳 VMP、多态壳、抽取策略、签名策略 | DONE | 关键底层能力已有开关或输入项，并在摘要区用能力矩阵展示当前启用/回退状态。 |
| P3-5 | 增加兼容推荐配置和强保护配置一键模板 | DONE | 新建任务页提供兼容推荐/强保护快捷按钮，保留当前 Android/Flutter 目标并自动调整保护强度、风险策略和方法选择档位。 |
| P3-6 | 上传 APK 后先做静态分析，再推荐保护策略 | DONE | 上传完成后自动调用智能方法分析并保存推荐保护映射，失败时降级为手动配置流程。 |
| P3-7 | Web 前端拆分 index.html/app.js 大文件 | DONE | 已拆出 js/jobs.js 和 js/report.js，app.js 从 2477 行降到 1746 行；新增拆分结构测试。 |

## P4：工程卫生和发布

| ID | 事项 | 状态 | 目的 |
| --- | --- | --- | --- |
| P4-1 | 清理 output、缓存、临时 APK、旧报告 | DONE | 已有 clean_workspace.py 管理 cache/root-artifacts/web-temp/output/android-build；默认不删 output，显式 --category output 或 --all 才纳入，新增 JSON dry-run 计划便于确认后清理。 |
| P4-2 | jks、测试 APK、Gradle zip、apktool jar 明确不进入源码仓库 | DONE | .gitignore 已覆盖敏感/大文件；新增 check_repo_hygiene.py 可在 CI 或本地检查忽略规则，并在 Git 仓库内拦截已跟踪的 forbidden 文件。 |
| P4-3 | release manifest 改成相对路径或构建时生成 | DONE | release_manifest_tool 默认生成相对 manifest 路径，当前 release_manifest.json 已去掉本机绝对路径；需要绝对路径时显式传 --absolute-paths。 |
| P4-4 | 文档补齐：签名流程、OLLVM 配置、保护档位、兼容问题排查 | DONE | 已新增 docs/OPERATIONS.md，覆盖外部签名、OLLVM required/best-effort、兼容/强保护档位、方法保护排查、Web 任务和发布清单。 |
| P4-5 | CI 增加单测、场景 APK 构建、可选设备冒烟测试 | DONE | CI 已覆盖 Python 单测、仓库卫生、release manifest、场景 APK 构建；设备语义 smoke 作为 workflow_dispatch 自托管 android runner 可选任务。 |

## P5：高阶对抗长期项

| ID | 事项 | 状态 | 目的 |
| --- | --- | --- | --- |
| P5-0 | 现代 Hook 注入链检测覆盖 | DONE | 补齐 LSPosed/Riru/Zygisk/LSPatch、Dobby/Whale、KernelSU/APatch 等现代注入/root 链路的 native/Java 静态检测。 |
| P5-1 | Frida/Xposed/LSPosed 对抗实验室 | TODO | 持续更新检测能力。 |
| P5-2 | dump 工具回归测试：dump dex、fridump、内存扫描、hook DexFile | DONE | 新增 tools/dump_resistance_check.py + 11 离线单测；模拟器 5/5 PASS:DEX 封存 2/2、/proc/mem 拒绝、loose DEX 不暴露、AI 诱饵 canary 在 APK 中。 |
| P5-3 | 检测 app_process、zygote、SELinux、系统服务完整性 | TODO | 面向定制 ROM/高级环境。 |
| P5-4 | 研究硬件断点、调试寄存器检测可行性 | TODO | 对抗更高阶调试。 |
| P5-5 | TEE/KeyStore/远程密钥策略研究 | TODO | 面向内核级 dump 场景。 |
| P5-6 | 保护策略遥测：失败率、机型、Android 版本、耗时 | TODO | 商业化必备。 |
| P5-7 | AI canary / AI decoy 模块 | DONE | packer/ai_decoy.py:per-build 唯一 canary 织进假 AES key/假 endpoints/假 license flag,写到 assets/;--ai-decoy CLI,商业模式自动启用;报告记录 canary 用于溯源;真机验证不影响业务语义。 |
| P5-8 | AI 一键脱壳回归实验室 | TODO | 自动跑 Frida hook、DexFile/InMemoryDexClassLoader dump、jadx、字符串扫描和 LLM 摘要检查，验证每次构建是否会被模板化自动还原。 |
| P5-9 | 稳定 hook 边界对抗回归 | TODO | 针对 ClassLoader、DexFile、JNIEnv Call*Method、nativeDecrypt、mmap/mprotect/memcpy 等常见 Agent hook 点建立检测和回归脚本。 |
| P5-10 | 诱饵取证与服务端风控联动 | TODO | 假 API、假 canary、假 flag 被访问或提交时，提高设备/IP/账号风险分，并联动限流、封禁、WAF/CDN 策略。 |

## P6：商业上线与运营风控

| ID | 事项 | 状态 | 目的 |
| --- | --- | --- | --- |
| P6-0 | 商业默认 profile 固化 | DONE | balanced/compat 在任何 policy 下经 RiskResponsePolicy 封顶到 RESTRICT，root/模拟器检测默认不阻断；TERMINATE 仅 strict/commercial 可达。 |
| P6-1 | 风险策略从“杀进程”改成分级响应矩阵 | DONE | 新增 RiskResponsePolicy（ALLOW/MONITOR/CHALLENGE/RESTRICT/TERMINATE）+ RiskState + 公开 API EnkoRuntime；ProxyApplication/Watchdog 接入；新增 javac 行为矩阵测试，全量 233 passed, 1 skipped。 |
| P6-2 | 服务端二次校验方案 | TODO | 授权、支付、会员、资产和风控结果必须服务端确认，本地校验只做第一层，token 绑定签名、版本、设备风险和请求上下文。 |
| P6-3 | 商业遥测与兼容性看板 | TODO | 采集 crash、ANR、启动耗时、点击响应、保护降级、设备型号、Android 版本、ABI、ROM 指纹，用于灰度决策。 |
| P6-4 | 灰度发布与一键回滚 | TODO | release manifest 增加灰度批次、保护 profile、风险策略和回滚目标；线上异常时可快速切回低强度保护包。 |
| P6-5 | Web UI 商业上线提示 | DONE | 5 个风险策略按钮加 hover tooltip 区分商业/兼容/调试场景；Root/模拟器/DEX 页封存/代理-VPN 四开关加兼容性警告；摘要面板新增「可终止/不杀进程」标签；能力矩阵新增「风险响应」行；node --check 通过，全量 233 passed。 |
| P6-6 | 边缘风控联动设计 | TODO | 规划 IP 封禁、CDN、WAF、互联网出口、负载均衡和后端风控的职责边界，避免只在 APK 侧做孤立判断。 |

## 近期执行顺序

1. P2-4：invoke/field/array/JNI 边界扰动首版，降低 Agent hook 一把抓的稳定性。
2. P2-1/P2-2：VMP 可变长度指令和字段布局随机化。
3. P5-7/P5-8：AI canary/decoy 与一键脱壳回归实验室。
4. P6-0/P6-1/P6-5：商业默认策略、分级响应和 Web 上线提示。
5. P6-2/P6-3/P6-4/P6-6：服务端校验、遥测、灰度回滚和边缘风控联动。
