# Enko APK Hardening

Enko is an Android APK hardening pipeline focused on local, offline protection.
It combines a Java shell, native runtime gates, encrypted payload loading,
method-level code protection (Extract / VMP DEX / DEX2C), and Flutter-aware
native-core integrity/hook monitoring.

## Legal Scope

Use only on applications you own or are explicitly authorized to protect.

## Quick Index

- [Requirements](#requirements)
- [Build Shell and Target APKs](#build-shell-and-target-apks)
- [Quick Start: Harden and Sign in Script](#quick-start-harden-and-sign-in-script)
- [Quick Start: Harden Unsigned (External Signing Mode)](#quick-start-harden-unsigned-external-signing-mode)
- [Hardening Profiles (Practical Defaults)](#hardening-profiles-practical-defaults)
- [Target Types: Java-first vs Flutter-first](#target-types-java-first-vs-flutter-first)
- [Protection Map (Unified Method-Level Config)](#protection-map-unified-method-level-config)
- [Versioned Release Metadata (Update-Friendly)](#versioned-release-metadata-update-friendly)
- [Runtime Gates (What Must Pass Before Payload Decrypt)](#runtime-gates-what-must-pass-before-payload-decrypt)
- [Report JSON (CI Gate Input)](#report-json-ci-gate-input)
- [Troubleshooting Startup Kills](#troubleshooting-startup-kills)
- [Update Strategy (Engine vs Rules)](#update-strategy-engine-vs-rules)

## Key Capabilities

1. Encrypted payload DEX package (AES-GCM) with optional zlib compression.
2. Runtime identity checks (package name + signing cert SHA-256 pin).
3. Native anti-debug and anti-hook gates (ptrace, tracer, maps/thread/fd scan, inline-hook checks).
4. Native anti-dump protections (PR_SET_DUMPABLE=0, watchdog scans, MADV_DONTDUMP, memory wipe).
5. Risk policy engine (`block` / `log`) with profiles (`strict` / `balanced` / `compat`).
6. Network risk checks (proxy, VPN, user CA, known capture apps).
7. Method-level protections:
- Phase 4.1: instruction extraction (encrypted restore blob).
- Phase 4.2: DEX2C translation for selected methods.
- Phase 4.3: VMP DEX compilation + JNI stub registration.
8. Per-APK random payload key patching into `libagpcore.so`.
9. Security report JSON for CI gating (`score`, `grade`, `compiled` counts).
10. Optional external native VMP pass for selected `.so` libraries.
11. Flutter-aware report mode (`--flutter-mode`) so DEX coverage is treated as secondary when the target is native-core heavy.
12. Independent `libapp.so` / `libflutter.so` integrity gates in addition to aggregate native-libs integrity.
13. Native mapped-code guard for `libapp.so` / `libflutter.so` executable segments.

## Hardening Profiles (Practical Defaults)

Use one of the following baseline profiles, then tune method map and thresholds.

For Flutter targets, add `--flutter-mode` to the hardening command and use
`packer/auto_protect_map.py --flutter-mode` when generating a method map.

### 1) Online Production (strict, fail-close)

```bash
python packer/harden_apk.py \
  --input-apk app-release.apk \
  --shell-apk shell-app/app/build/outputs/apk/release/app-release-unsigned.apk \
  --output-apk app-hardened-unsigned.apk \
  --risk-policy block \
  --risk-profile strict \
  --block-proxy-vpn \
  --detect-root \
  --detect-emulator \
  --per-apk-key \
  --protection-map full-open-protect.txt \
  --ndk-path /path/to/ndk \
  --min-security-score 90 \
  --report-json hardened.report.json
```

Sign `app-hardened-unsigned.apk` afterwards with the app's original release certificate.

### 2) Lab / Emulator Verification (less blocking)

```bash
python packer/harden_apk.py \
  --input-apk app-release.apk \
  --shell-apk shell-app/app/build/outputs/apk/release/app-release-unsigned.apk \
  --output-apk app-hardened-lab.apk \
  --risk-policy log \
  --risk-profile compat \
  --allow-proxy-vpn \
  --disable-root-check \
  --disable-emulator-check \
  --per-apk-key \
  --report-json hardened.lab.report.json
```

### 3) Commercial Baseline Mode (auto constraints)

```bash
python packer/harden_apk.py \
  --input-apk app-release.apk \
  --shell-apk shell-app/app/build/outputs/apk/release/app-release-unsigned.apk \
  --output-apk app-hardened-unsigned.apk \
  --commercial-mode \
  --protection-map full-open-protect.txt \
  --ndk-path /path/to/ndk \
  --report-json hardened.report.json
```

## Target Types: Java-first vs Flutter-first

Use different success metrics depending on where the real business logic lives.

### Java-first APK

- Primary KPI: method-level protection density (`extract` / `vmp_dex` / `dex2c`).
- Strong signal: `method_protection.protectable_coverage_ratio` in report JSON.
- Focus packages: your real app packages, not support libraries.

### Flutter-first APK

- Primary KPI: native-core integrity and runtime hook resistance.
- DEX protection is still useful, but mostly for shell code and plugin bridges.
- Strong signals in report JSON:
  - `target_runtime.mode=flutter`
  - `target_runtime.native_core.libapp.present`
  - `target_runtime.native_core.libapp.integrity_pinned`
  - `target_runtime.native_core.libflutter.integrity_pinned`
  - `target_runtime.native_core.hook_watch_targets`

Practical rule:

- If the target contains `libapp.so` or `libflutter.so`, treat DEX coverage as secondary.
- If the target is Java/Kotlin business-heavy, treat DEX coverage as primary.

## Repository Layout

- `packer/harden_apk.py`: core hardening and packaging pipeline.
- `packer/auto_protect_map.py`: heuristic method selector (no AI required).
- `packer/release_manifest_tool.py`: release metadata build/validate tool.
- `shell-app/`: runtime shell app and native protection runtime.
- `demo-app/`: sample target app.
- `release/`: versioned metadata templates (`engine/rules/policy/presets`).

## Requirements

- Python 3.9+
- `pycryptodome`
- JDK 11+
- Android SDK build-tools (`zipalign`, `apksigner`)
- `apktool`
- Android NDK (required for VMP DEX / DEX2C)
- Optional: external native VMP CLI

Install Python dependency:

```bash
pip install pycryptodome
```

For development and tests:

```bash
pip install -r requirements-dev.txt
pytest
```

Optional Android semantic smoke test for the small flag APK:

```bash
python tools/android_semantic_smoke.py --apk test_apks/small_app/app/build/outputs/apk/debug/app-hardened-current.apk
```

One-command rebuild + Android semantic regression for the small flag APK:

```bash
python tools/run_small_semantic_regression.py --preset stable --preset light
```

Or through pytest, when an emulator/device is connected:

```bash
ENKO_RUN_ANDROID_E2E=1 ENKO_E2E_APK=test_apks/small_app/app/build/outputs/apk/debug/app-hardened-current.apk pytest tests/test_android_semantic_smoke.py -v
```

Workspace cleanup:

```bash
# Preview conservative cleanup: caches, root artifacts, and web temp files.
python tools/clean_workspace.py

# Apply conservative cleanup.
python tools/clean_workspace.py --apply

# Optional deep cleanup of generated APK outputs or Android build caches.
python tools/clean_workspace.py --category output --apply
python tools/clean_workspace.py --category android-build --apply
```

## Build Shell and Target APKs

Maintenance build (release without R8 obfuscation):

```bash
cd shell-app
gradle assembleRelease -PenkoAllowWeakRelease=true
```

Production-oriented release (R8 obfuscation enabled):

```bash
cd demo-app
gradle assembleRelease -PenkoReleaseObfuscate=true

cd ../shell-app
gradle assembleRelease -PenkoReleaseObfuscate=true
```

Notes:
- `shell-app` release artifact is typically:
`shell-app/app/build/outputs/apk/release/app-release-unsigned.apk`
- `demo-app` release artifact is typically:
`demo-app/app/build/outputs/apk/release/app-release.apk`

## Quick Start: Harden and Sign in Script

```bash
python packer/harden_apk.py \
  --input-apk demo-app/app/build/outputs/apk/release/app-release.apk \
  --shell-apk shell-app/app/build/outputs/apk/release/app-release-unsigned.apk \
  --output-apk demo-app-hardened-signed.apk \
  --sign \
  --keystore enko-ci.jks \
  --ks-pass enkotest \
  --key-alias enko \
  --key-pass enkotest \
  --risk-policy block \
  --risk-profile strict \
  --block-proxy-vpn \
  --per-apk-key
```

## Quick Start: Harden Unsigned (External Signing Mode)

Use this when you must sign outside the hardening service.

```bash
python packer/harden_apk.py \
  --input-apk app-release.apk \
  --shell-apk shell-app/app/build/outputs/apk/release/app-release-unsigned.apk \
  --output-apk app-hardened-unsigned.apk \
  --risk-policy block
```

Then sign with your own certificate:

```bash
apksigner sign \
  --ks your-release.jks \
  --ks-key-alias yourAlias \
  --ks-pass pass:yourStorePass \
  --key-pass pass:yourKeyPass \
  --out app-hardened-signed.apk \
  app-hardened-unsigned.apk
```

Important:
- Runtime signature pin defaults to the input APK certificate SHA-256 when available.
- If final signing certificate differs from input APK cert, pass `--sign-cert-sha256` explicitly.

## Protection Map (Unified Method-Level Config)

`--protection-map` format:

```text
# level: 0=none, 1=extract, 2=vmp, 3=dex2c
Lcom/example/app/Crypto;->* 2
Lcom/example/app/License;->verify(Ljava/lang/String;)Z 3
Lcom/example/app/SplashActivity;->onCreate(Landroid/os/Bundle;)V 1
```

Method spec grammar:
- `Lcom/example/Foo;->bar` (all overloads)
- `Lcom/example/Foo;->bar(II)V` (exact signature)
- `Lcom/example/Foo;->*` (all class methods)

## Auto-Generate Protection Map (No AI)

```bash
python packer/auto_protect_map.py \
  --input-apk app-release.apk \
  --output-map auto-protect.txt \
  --include-package com.example.app \
  --vmp-count 24 \
  --dex2c-count 4 \
  --extract-count 10 \
  --report-json auto-protect.report.json
```

Flutter-oriented generation:

```bash
python packer/auto_protect_map.py \
  --input-apk app-release.apk \
  --output-map auto-protect-flutter.txt \
  --flutter-mode \
  --vmp-count 120 \
  --dex2c-count 24 \
  --extract-count 220 \
  --report-json auto-protect-flutter.report.json
```

`--flutter-mode` biases selection away from `io.flutter.*` framework noise and
toward host/plugin bridge methods when present.

Use generated map directly:

```bash
python packer/harden_apk.py \
  --input-apk app-release.apk \
  --shell-apk shell-app/app/build/outputs/apk/release/app-release-unsigned.apk \
  --output-apk app-hardened.apk \
  --protection-map auto-protect.txt \
  --ndk-path /path/to/ndk \
  --min-vmp-dex-count 20 \
  --min-dex2c-count 3 \
  --min-extract-count 8
```

## Versioned Release Metadata (Update-Friendly)

Use versioned metadata to separate stable engine updates from frequent rules/policy updates.

Metadata files:
- `release/engine_manifest.json`
- `release/rules.json`
- `release/policy.json`
- `release/presets.json`

Build release manifest:

```bash
python packer/release_manifest_tool.py build \
  --engine-manifest release/engine_manifest.json \
  --rules-file release/rules.json \
  --policy-file release/policy.json \
  --presets-file release/presets.json \
  --protection-map full-open-protect.txt \
  --map-version full-open.v1 \
  --output release/release_manifest.json
```

Validate manifest and hashes:

```bash
python packer/release_manifest_tool.py validate \
  --manifest release/release_manifest.json \
  --check-files
```

Attach manifest to hardening jobs:

```bash
python packer/harden_apk.py \
  ... \
  --release-manifest release/release_manifest.json \
  --report-json hardened.report.json
```

When provided, `release_meta` is embedded into report JSON for audit and rollback traceability.

## Report JSON (CI Gate Input)

Typical report fields:

- `score`, `max_score`, `grade`: overall hardening rating.
- `controls[]`: control-by-control status and weight.
- `recommendations[]`: missing controls to improve.
- `compiled.extract|vmp_dex|dex2c`: method-level protection hit counts.
- `method_protection.*`: request hit ratio, protectable coverage ratio, and coverage grade.
- `target_runtime.mode`: `standard` or `flutter`.
- `target_runtime.native_core.*`: native-core presence, independent `libapp.so` / `libflutter.so` integrity pins, and hook watch targets.
- `risk_policy`, `risk_profile`: effective runtime policy.
- `output_apk`: final output artifact path.

Use this in CI for hard fail conditions:

1. `score < threshold`
2. `compiled` counts lower than expected
3. policy drift (`risk_policy`/`risk_profile` changed unexpectedly)

Interpretation notes:

- For Java-first apps, `method_protection` is a primary score driver.
- For Flutter-first apps, the report still shows DEX coverage, but it is not the main strength indicator.
- In Flutter mode, `flutter-native-core-integrity` is expected to be present when Flutter core libraries exist.

## Commercial Baseline Mode

`--commercial-mode` enforces production constraints:
- Requires signing in-script.
- Forbids all fail-open flags.
- Requires `risk-policy=block`, `risk-profile=strict`, `block-proxy-vpn`.
- Requires per-APK key.
- Verifies release obfuscation mapping (unless `--allow-weak-release`).
- Defaults `--min-security-score` to 90 if not set.

## Selected `harden_apk.py` Flags

- Core I/O:
- `--input-apk`, `--shell-apk` or `--shell-dex`, `--output-apk`
- Signing:
- Default is unsigned external signing; use `--sign` with `--keystore`, `--ks-pass`, `--key-alias`, `--key-pass` only when that keystore is the app's original certificate.
- `--skip-sign`
- Runtime identity:
- `--sign-cert-sha256`
- Risk controls:
- `--risk-policy`, `--risk-profile`, `--block-proxy-vpn|--allow-proxy-vpn`, `--detect-root|--disable-root-check`, `--detect-emulator|--disable-emulator-check`
- Method protections:
- `--protection-map`
- `--extract-methods`, `--vmp-dex-methods`, `--dex2c-methods`
- `--vmp-dex-obfuscation-preset stable|light|medium` (`light` is default)
- `--vmp-dex-split-prob`, `--vmp-dex-junk-ratio`, `--vmp-dex-inline-junk-ratio`
- `--ndk-path`
- Shell metadata:
- `--polymorphic-shell` randomizes the shell package, high-signal shell
  class/method names, and native-layer blob filenames.
- Fail-close thresholds:
- `--min-extract-count`, `--min-vmp-dex-count`, `--min-dex2c-count`
- Quality gate:
- `--min-security-score`, `--report-json`
- Release metadata:
- `--release-manifest`
- Packaging tools:
- `--apktool`, `--zipalign`, `--apksigner`, `--timeout`

Run `python packer/harden_apk.py --help` for the full and current flag list.

## Optional Native VMP Stage

If you have an external native VMP CLI, you can virtualize selected native libs
after decode and before repack:

```bash
python packer/harden_apk.py \
  --input-apk app-release.apk \
  --shell-apk shell-app/app/build/outputs/apk/release/app-release-unsigned.apk \
  --output-apk app-hardened.apk \
  --vmp-command-template "vmprotect_con.exe -i {input} -o {output}" \
  --vmp-target-libs libagpcore.so
```

Template placeholders:
- `{input}`: input `.so` absolute path
- `{output}`: output `.so` absolute path
- `{abi}`: ABI directory name
- `{lib}`: library filename

## Runtime Blob Files in Hardened APK

The pipeline writes encrypted/runtime blobs into ABI library directories. With
`--polymorphic-shell`, the `libvt*.so` blob names below are same-length
randomized per build and patched into the shell DEX:

- `lib/<abi>/libvtcfg.so` (encrypted runtime config)
- `lib/<abi>/libvtpl.so` (encrypted payload package)
- `lib/<abi>/libvtvm.so` (VMP DEX blob, when enabled)
- `lib/<abi>/libvtex.so` (extract blob, when enabled)
- `lib/<abi>/libagpstub.so` (VMP JNI stubs, when enabled)
- `lib/<abi>/libagpjnix.so` (DEX2C output, when enabled)
- `lib/<abi>/libagpcore.so` (native runtime core)

The encrypted payload blob is also wrapped in a per-build byte envelope before
being stored, so the stable AES-GCM payload magic is not visible in the APK.

The encrypted runtime config inside the config blob now includes:

- `shellDexSha256`
- `nativeLibsSha256`
- `libAppSha256` (when `libapp.so` exists in the target)
- `libFlutterSha256` (when `libflutter.so` exists in the target)
- `buildId`, `buildEpochSec`, `buildVersionCode`

## Runtime Gates (What Must Pass Before Payload Decrypt)

`nativeDecryptWithEmbeddedKey()` is not allowed to run unless all required gates
have been opened.

Current gate order:

1. Native identity check from decrypted config
   - package name
   - signing cert SHA-256
2. Shell `classes.dex` integrity
3. Aggregate native-libs integrity
4. Independent `libapp.so` / `libflutter.so` integrity when present
5. Native rollback / replay guard
6. Native startup risk gate
7. Only then payload decryption proceeds

Why this matters:

- Deleting a Java call is no longer enough if the corresponding native gate is still closed.
- Flutter targets now have dedicated `libapp.so` / `libflutter.so` gates instead of relying only on aggregate native-libs hashing.

## Runtime Flow (High Level)

```text
[EnkoInitProvider.onCreate]
  -> System.loadLibrary("agpcore")
     -> .init_array precheck
     -> JNI_OnLoad: RegisterNatives + anti-debug + anti-dump

[ProxyApplication.attachBaseContext]
  -> read/decrypt libvtcfg.so
  -> enforce identity + shell dex integrity + native libs integrity
  -> optional independent libapp.so / libflutter.so integrity
  -> enforce rollback/replay guard
  -> startup risk gate
  -> decrypt payload blob (libvtpl.so)
  -> optional extract bind/restore
  -> create payload classloader
  -> optional DEX2C register
  -> optional VMP load/register
  -> bind real Application
  -> watchdog continues runtime risk monitoring
```

## Native OLLVM / Hikari Obfuscation

Shell native builds enable Hikari/OLLVM by default. Override the compiler path
with `-PenkoOllvmClang=...` or `ENKO_OLLVM_CLANG`; the repository default is
`/opt/enko/toolchains/hikari-llvm19/install/bin/clang`.

On Linux servers, install the bundled default toolchain path with:

```bash
cd /opt/enko
bash tools/install_hikari_ollvm.sh
echo "ENKO_OLLVM_CLANG=/opt/enko/toolchains/hikari-llvm19/install/bin/clang" >> /etc/enko/config.env
systemctl restart enko-web
```

Gradle example:

```bash
cd shell-app
gradle assembleRelease -PenkoReleaseObfuscate=true
```

Maintenance builds can disable native obfuscation explicitly:

```bash
gradle assembleRelease -PenkoEnableOllvm=false -PenkoAllowWeakRelease=true
```

Direct CMake example:

```bash
cmake -DENKO_OLLVM=ON \
      -DENKO_OLLVM_CLANG=/path/to/hikari-clang \
      -DANDROID_ABI=arm64-v8a \
      -DANDROID_NDK=/path/to/ndk \
      shell-app/app/src/main/cpp
```

In current CMake config:
- Hikari targets: `enko_aes.c`, `enko_gcm.c`, `enko_integrity.c`, `enko_anti_debug.c`, `enko_anti_dump.c`, `enko_extract.c`
- NDK targets: `enko_vmp.c`, `enko_jni.c`, `enko_key.c`

`enko_key.c` intentionally stays on the NDK path because it contains
byte-exact per-APK key slots patched by the packer after compilation.

DEX2C output is also Hikari/OLLVM-enabled by default. When `--dex2c-methods`
or protection-map level `3` is used, the generated `libagpjnix.so` is compiled
with Hikari passes (`cffobf`, `subobf`, `bcfobf`, `splitobf`, `strcry`) using
`--dex2c-ollvm-clang` or `ENKO_OLLVM_CLANG`. For compatibility this path is
best-effort by default: if Hikari is unavailable or fails, DEX2C retries normal
NDK clang. Use `--dex2c-ollvm-required` to make that fail-closed; commercial
mode enables this requirement automatically when DEX2C is active.

## Troubleshooting Startup Kills

If app exits immediately after install/open, check in this order:

1. Signature pin mismatch:
- Runtime cert pin may not match final signing cert.
- Fix with `--sign-cert-sha256` or sign with the same cert as input.
2. Native integrity gate mismatch:
- `shellDexSha256`, `nativeLibsSha256`, `libAppSha256`, or `libFlutterSha256` may no longer match the final package contents.
- Re-run hardening after any shell/native binary change; do not reuse stale config blobs.
3. Strict risk policy in test environment:
- `block + strict + detect-emulator/root + block-proxy-vpn` can kill app on emulator, rooted phone, or proxy/VPN lab.
- For test-only builds use `--risk-policy log --risk-profile compat --disable-root-check --disable-emulator-check --allow-proxy-vpn`.
4. Method protection compilation not effective:
- If `--vmp-dex-methods` / `--dex2c-methods` is set without valid NDK, build may fail or protections may be missing.
- Ensure `--ndk-path` is valid and verify `compiled` counts in report JSON.
5. Fail-close thresholds too high:
- `--min-extract-count`, `--min-vmp-dex-count`, `--min-dex2c-count`, `--min-security-score` can stop packaging intentionally.
- Tune thresholds according to target app size and map coverage.
6. Flutter target expected more DEX protection than it can realistically carry:
- A Flutter APK may have very little business logic in DEX.
- In that case, focus on `target_runtime.native_core.*` instead of forcing unrealistically high DEX thresholds.
7. Release obfuscation guard triggered:
- If release obfuscation cannot be verified, packaging is blocked unless `--allow-weak-release` is set.

## Update Strategy (Engine vs Rules)

Treat updates as two lanes:

- Fast lane (frequent): `release/rules.json`, `release/policy.json`, `release/presets.json`, protection map files.
- Slow lane (careful): `shell-app` native/runtime code and `packer/harden_apk.py` core engine.

Recommended workflow:

1. Keep `engine` version stable across minor rule updates.
2. Rebuild `release_manifest.json` for every policy/map change.
3. Archive previous stable `engine+rules+policy+map` tuple for rollback.
4. Gate rollout with report JSON thresholds on a device matrix.
5. Only bump engine version when runtime behavior or binary format changes.

## Known Limits

- Anti-dump and anti-hook are best-effort, not absolute.
- All-local protection has no server-side attestation by design.
- Over-aggressive protection maps can impact startup stability/performance.
- `libapp.so` / `libflutter.so` hook detection is memory-baseline based; it is meant to catch post-load tamper, not replace full remote attestation.

## Recommended Release Checklist

1. Build demo and shell release with obfuscation.
2. Validate release manifest and hashes.
3. Harden with fail-close thresholds and report output.
4. Verify signature pin target and final signing cert consistency.
5. Run device matrix smoke tests (real device, emulator, proxy/VPN, rooted env).
6. Keep previous stable `engine/rules/policy/map` combination for immediate rollback.
