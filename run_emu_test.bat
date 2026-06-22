@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ============================================
echo  Enko APK Hardening - Emulator Test Runner
echo ============================================
echo.

set "PROJECT_DIR=%~dp0"
cd /d "%PROJECT_DIR%"

:: ---- Paths ----
set "DEMO_APK=demo-app\app\build\outputs\apk\release\app-release.apk"
set "SHELL_APK=shell-app\app\build\outputs\apk\release\app-release-unsigned.apk"
set "OUTPUT_APK=demo-app-hardened-emu-test.apk"
set "REPORT_JSON=demo-app-hardened-emu-test.report.json"
set "PROTECT_MAP=full-open-protect.txt"
set "KEYSTORE=enko-ci.jks"
set "KS_PASS=enkotest"
set "KEY_ALIAS=enko"
set "KEY_PASS=enkotest"

:: ---- Auto-detect NDK ----
set "NDK_PATH="
if defined ANDROID_NDK_HOME (
    set "NDK_PATH=%ANDROID_NDK_HOME%"
) else if defined ANDROID_NDK_ROOT (
    set "NDK_PATH=%ANDROID_NDK_ROOT%"
) else (
    :: Try common locations
    for /d %%D in ("%LOCALAPPDATA%\Android\Sdk\ndk\*") do set "NDK_PATH=%%D"
)
if not defined NDK_PATH (
    echo [WARN] NDK not found. VMP/DEX2C compilation may fail.
    echo        Set ANDROID_NDK_HOME or install NDK via Android Studio.
    echo        Continuing anyway...
)
echo [INFO] NDK_PATH=%NDK_PATH%

:: ---- Check prerequisites ----
echo.
echo [Step 0] Checking prerequisites...

if not exist "%DEMO_APK%" (
    echo [ERROR] Demo APK not found: %DEMO_APK%
    echo         Build it first: cd demo-app ^&^& gradlew assembleRelease
    goto :fail
)
echo   ✓ Demo APK found

if not exist "%SHELL_APK%" (
    echo [ERROR] Shell APK not found: %SHELL_APK%
    echo         Build it first: cd shell-app ^&^& gradlew assembleRelease -PenkoAllowWeakRelease=true
    goto :fail
)
echo   ✓ Shell APK found

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH
    goto :fail
)
echo   ✓ Python found

adb version >nul 2>&1
if errorlevel 1 (
    echo [WARN] adb not found — skip install step
    set "SKIP_INSTALL=1"
) else (
    echo   ✓ adb found
)
echo.

:: ---- Step 1: Harden with full protection, emulator/root disabled ----
echo ============================================
echo [Step 1] Hardening APK (full-open, emu-safe)
echo ============================================
echo   Input:      %DEMO_APK%
echo   Shell:      %SHELL_APK%
echo   Output:     %OUTPUT_APK%
echo   Protection: %PROTECT_MAP%
echo   Emulator:   DISABLED
echo   Root check: DISABLED
echo   Risk:       log / compat
echo.

set "HARDEN_CMD=python packer\harden_apk.py"
set "HARDEN_CMD=%HARDEN_CMD% --input-apk %DEMO_APK%"
set "HARDEN_CMD=%HARDEN_CMD% --shell-apk %SHELL_APK%"
set "HARDEN_CMD=%HARDEN_CMD% --output-apk %OUTPUT_APK%"
set "HARDEN_CMD=%HARDEN_CMD% --keystore %KEYSTORE%"
set "HARDEN_CMD=%HARDEN_CMD% --ks-pass %KS_PASS%"
set "HARDEN_CMD=%HARDEN_CMD% --key-alias %KEY_ALIAS%"
set "HARDEN_CMD=%HARDEN_CMD% --key-pass %KEY_PASS%"
set "HARDEN_CMD=%HARDEN_CMD% --risk-policy log"
set "HARDEN_CMD=%HARDEN_CMD% --risk-profile compat"
set "HARDEN_CMD=%HARDEN_CMD% --disable-root-check"
set "HARDEN_CMD=%HARDEN_CMD% --disable-emulator-check"
set "HARDEN_CMD=%HARDEN_CMD% --allow-proxy-vpn"
set "HARDEN_CMD=%HARDEN_CMD% --per-apk-key"
set "HARDEN_CMD=%HARDEN_CMD% --protection-map %PROTECT_MAP%"
set "HARDEN_CMD=%HARDEN_CMD% --report-json %REPORT_JSON%"
if defined NDK_PATH (
    set "HARDEN_CMD=%HARDEN_CMD% --ndk-path %NDK_PATH%"
)

echo [CMD] %HARDEN_CMD%
echo.
%HARDEN_CMD%

if errorlevel 1 (
    echo.
    echo [ERROR] Hardening failed! See output above.
    goto :fail
)

echo.
echo   ✓ Hardening complete: %OUTPUT_APK%
echo.

:: ---- Step 2: Show report ----
echo ============================================
echo [Step 2] Security Report
echo ============================================
if exist "%REPORT_JSON%" (
    type "%REPORT_JSON%"
    echo.
) else (
    echo   [WARN] Report not generated
)
echo.

:: ---- Step 3: Install on emulator ----
if defined SKIP_INSTALL (
    echo [SKIP] adb not available, skipping install
    goto :done
)

echo ============================================
echo [Step 3] Installing on emulator
echo ============================================

:: Check for connected devices
adb devices | findstr /R "emulator device$" >nul 2>&1
if errorlevel 1 (
    echo [WARN] No emulator/device connected. Start an emulator first.
    echo        Try: emulator -avd ^<name^> -writable-system
    goto :done
)

echo   Installing %OUTPUT_APK% ...
adb install -r "%OUTPUT_APK%"
if errorlevel 1 (
    echo [ERROR] Install failed
    goto :fail
)
echo   ✓ Installed successfully
echo.

:: ---- Step 4: Launch app ----
echo ============================================
echo [Step 4] Launching app on emulator
echo ============================================
adb shell am start -n com.example.demo/.MainActivity
if errorlevel 1 (
    echo [WARN] Could not launch app
) else (
    echo   ✓ App launched
)
echo.

:: ---- Step 5: Quick compatibility check ----
echo ============================================
echo [Step 5] Compatibility Check (5s wait)
echo ============================================
timeout /t 5 /nobreak >nul

:: Check if process is still alive
adb shell pidof com.example.demo >nul 2>&1
if errorlevel 1 (
    echo   ✗ App CRASHED — check logcat:
    echo     adb logcat -d -s EnkoDemo,ProxyApplication,agpcore,AndroidRuntime --format=brief
    adb logcat -d -s EnkoDemo,ProxyApplication,agpcore,AndroidRuntime --format=brief 2>nul | findstr /i "error exception crash fatal"
    goto :fail
) else (
    echo   ✓ App is running — no crash detected
)
echo.

:: Grab logcat for Enko-specific tags
echo [Logcat excerpt]
adb logcat -d -s EnkoDemo,ProxyApplication,agpcore --format=brief 2>nul | findstr /V "^$"
echo.

:done
echo ============================================
echo  TEST COMPLETE
echo ============================================
echo  Output APK:  %OUTPUT_APK%
echo  Report:      %REPORT_JSON%
echo.
echo  To test manually:
echo    adb shell am start -n com.example.demo/.MainActivity
echo    adb logcat -s EnkoDemo,ProxyApplication,agpcore
echo.
endlocal
exit /b 0

:fail
echo.
echo ============================================
echo  TEST FAILED — see errors above
echo ============================================
endlocal
exit /b 1
