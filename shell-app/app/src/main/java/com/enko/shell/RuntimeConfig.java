package com.enko.shell;

import java.util.Locale;
import java.util.Map;

final class RuntimeConfig {
    static final String POLICY_BLOCK = "block";
    static final String POLICY_DEGRADE = "degrade";
    static final String POLICY_WARN = "warn";
    static final String POLICY_LOG = "log";
    static final String POLICY_OFF = "off";
    static final String PROFILE_STRICT = "strict";
    static final String PROFILE_BALANCED = "balanced";
    static final String PROFILE_COMPAT = "compat";
    static final String COMPRESSION_NONE = "NONE";
    static final String COMPRESSION_ZLIB = "ZLIB";
    static final String VM_TIER_COMPAT = "compat";
    static final String VM_TIER_LIGHT = "light";
    static final String VM_TIER_STRONG = "strong";

    final String realApplicationClass;
    final String payloadCompression;
    final String expectedPackageName;
    final String expectedSignSha256;
    final String riskPolicy;
    final String riskProfile;
    final boolean blockProxyVpn;
    final boolean detectRoot;
    final boolean detectEmulator;
    final boolean protectDexPages;
    final boolean vmpEnabled;
    final String vmpVmTier;
    final boolean extractEnabled;
    final boolean extractOnDemand;
    final boolean dex2cEnabled;
    final boolean shellVmpEnabled;
    final boolean commercialMode;
    final String shellDexSha256;
    final String nativeLibsSha256;
    final String libAppSha256;
    final String libFlutterSha256;
    final String buildId;
    final long buildEpochSec;
    final long buildVersionCode;

    private RuntimeConfig(
            String realApplicationClass,
            String payloadCompression,
            String expectedPackageName,
            String expectedSignSha256,
            String riskPolicy,
            String riskProfile,
            boolean blockProxyVpn,
            boolean detectRoot,
            boolean detectEmulator,
            boolean protectDexPages,
            boolean vmpEnabled,
            String vmpVmTier,
            boolean extractEnabled,
            boolean extractOnDemand,
            boolean dex2cEnabled,
            boolean shellVmpEnabled,
            boolean commercialMode,
            String shellDexSha256,
            String nativeLibsSha256,
            String libAppSha256,
            String libFlutterSha256,
            String buildId,
            long buildEpochSec,
            long buildVersionCode
    ) {
        this.realApplicationClass = realApplicationClass;
        this.payloadCompression = payloadCompression;
        this.expectedPackageName = expectedPackageName;
        this.expectedSignSha256 = expectedSignSha256;
        this.riskPolicy = riskPolicy;
        this.riskProfile = riskProfile;
        this.blockProxyVpn = blockProxyVpn;
        this.detectRoot = detectRoot;
        this.detectEmulator = detectEmulator;
        this.protectDexPages = protectDexPages;
        this.vmpEnabled = vmpEnabled;
        this.vmpVmTier = vmpVmTier;
        this.extractEnabled = extractEnabled;
        this.extractOnDemand = extractOnDemand;
        this.dex2cEnabled = dex2cEnabled;
        this.shellVmpEnabled = shellVmpEnabled;
        this.commercialMode = commercialMode;
        this.shellDexSha256 = shellDexSha256;
        this.nativeLibsSha256 = nativeLibsSha256;
        this.libAppSha256 = libAppSha256;
        this.libFlutterSha256 = libFlutterSha256;
        this.buildId = buildId;
        this.buildEpochSec = buildEpochSec;
        this.buildVersionCode = buildVersionCode;
    }

    static RuntimeConfig fromMap(Map<String, String> map) {
        String realAppClass = requireValue(map, "realApplicationClass");

        String compression = requireValue(map, "payloadCompression").toUpperCase(Locale.US);
        if (!COMPRESSION_ZLIB.equals(compression)) {
            compression = COMPRESSION_NONE;
        }

        String expectedPackage = requireValue(map, "expectedPackageName");
        if (expectedPackage.isEmpty()) {
            throw new IllegalArgumentException("runtime config expectedPackageName is empty");
        }

        String signSha = normalizeSha256(requireValue(map, "expectedSignSha256"));
        if (signSha.isEmpty()) {
            throw new IllegalArgumentException("runtime config expectedSignSha256 is invalid");
        }

        String policy = requireValue(map, "riskPolicy").toLowerCase(Locale.US);
        if (!POLICY_BLOCK.equals(policy) && !POLICY_DEGRADE.equals(policy)
                && !POLICY_WARN.equals(policy) && !POLICY_LOG.equals(policy)
                && !POLICY_OFF.equals(policy)) {
            throw new IllegalArgumentException("runtime config riskPolicy is invalid: " + policy);
        }
        String profile = normalizeRiskProfile(requireValue(map, "riskProfile"));

        boolean blockProxyVpn = parseBoolStrict(requireValue(map, "blockProxyVpn"), "blockProxyVpn");
        boolean detectRoot = parseBoolStrict(requireValue(map, "detectRoot"), "detectRoot");
        boolean detectEmulator = parseBoolStrict(requireValue(map, "detectEmulator"), "detectEmulator");
        boolean protectDexPages = parseBoolOptional(map, "protectDexPages", true);
        boolean vmpEnabled = parseBoolStrict(requireValue(map, "vmpEnabled"), "vmpEnabled");
        String vmpVmTier = normalizeVmpVmTier(map.get("vmpVmTier"));
        boolean extractEnabled = parseBoolStrict(requireValue(map, "extractEnabled"), "extractEnabled");
        boolean extractOnDemand = parseBoolOptional(map, "extractOnDemand", false);
        boolean dex2cEnabled = parseBoolStrict(requireValue(map, "dex2cEnabled"), "dex2cEnabled");
        boolean shellVmpEnabled = parseBoolOptional(map, "shellVmpEnabled", false);
        boolean commercialMode = parseBoolOptional(map, "commercialMode", false);

        String shellDexSha = normalizeSha256(requireValue(map, "shellDexSha256"));
        if (shellDexSha.isEmpty()) {
            throw new IllegalArgumentException("runtime config shellDexSha256 is invalid");
        }
        String nativeLibsSha = normalizeSha256(requireValue(map, "nativeLibsSha256"));
        if (nativeLibsSha.isEmpty()) {
            throw new IllegalArgumentException("runtime config nativeLibsSha256 is invalid");
        }
        String libAppSha = parseOptionalSha256(map, "libAppSha256");
        String libFlutterSha = parseOptionalSha256(map, "libFlutterSha256");

        String buildId = normalizeBuildId(requireValue(map, "buildId"));
        if (buildId.isEmpty()) {
            throw new IllegalArgumentException("runtime config buildId is invalid");
        }
        long buildEpochSec = parseLongStrict(requireValue(map, "buildEpochSec"), "buildEpochSec");
        long buildVersionCode = parseLongStrict(requireValue(map, "buildVersionCode"), "buildVersionCode");
        if (buildEpochSec <= 0L || buildVersionCode <= 0L) {
            throw new IllegalArgumentException("runtime config build epoch/version must be > 0");
        }

        return new RuntimeConfig(
                realAppClass,
                compression,
                expectedPackage,
                signSha,
                policy,
                profile,
                blockProxyVpn,
                detectRoot,
                detectEmulator,
                protectDexPages,
                vmpEnabled,
                vmpVmTier,
                extractEnabled,
                extractOnDemand,
                dex2cEnabled,
                shellVmpEnabled,
                commercialMode,
                shellDexSha,
                nativeLibsSha,
                libAppSha,
                libFlutterSha,
                buildId,
                buildEpochSec,
                buildVersionCode
        );
    }

    boolean shouldBlockOnRisk() {
        return POLICY_BLOCK.equals(riskPolicy) || POLICY_DEGRADE.equals(riskPolicy);
    }

    boolean isWarnPolicy() {
        return POLICY_WARN.equals(riskPolicy);
    }

    boolean isOffPolicy() {
        return POLICY_OFF.equals(riskPolicy);
    }

    boolean isDegradePolicy() {
        return POLICY_DEGRADE.equals(riskPolicy);
    }

    boolean requiresShellVmp() {
        return shellVmpEnabled
                && (commercialMode
                || (POLICY_BLOCK.equals(riskPolicy)
                && PROFILE_STRICT.equals(riskProfile)));
    }

    int vmpTierCode() {
        if (VM_TIER_COMPAT.equals(vmpVmTier)) {
            return 0;
        }
        if (VM_TIER_STRONG.equals(vmpVmTier)) {
            return 2;
        }
        return 1;
    }

    private static String requireValue(Map<String, String> map, String key) {
        String v = map.get(key);
        if (v == null) {
            throw new IllegalArgumentException("runtime config missing key: " + key);
        }
        return v.trim();
    }

    private static boolean parseBoolStrict(String raw, String key) {
        if ("1".equals(raw) || "true".equalsIgnoreCase(raw)) {
            return true;
        }
        if ("0".equals(raw) || "false".equalsIgnoreCase(raw)) {
            return false;
        }
        throw new IllegalArgumentException("runtime config " + key + " must be 0/1/true/false");
    }

    private static boolean parseBoolOptional(
            Map<String, String> map, String key, boolean defaultValue) {
        String raw = map.get(key);
        if (raw == null || raw.trim().isEmpty()) {
            return defaultValue;
        }
        return parseBoolStrict(raw.trim(), key);
    }

    private static String normalizeRiskProfile(String raw) {
        String value = raw == null ? "" : raw.trim().toLowerCase(Locale.US);
        if (PROFILE_STRICT.equals(value)) {
            return PROFILE_STRICT;
        }
        if (PROFILE_COMPAT.equals(value)) {
            return PROFILE_COMPAT;
        }
        if (PROFILE_BALANCED.equals(value)) {
            return PROFILE_BALANCED;
        }
        throw new IllegalArgumentException("runtime config riskProfile is invalid: " + value);
    }

    private static String normalizeVmpVmTier(String raw) {
        String value = raw == null ? "" : raw.trim().toLowerCase(Locale.US);
        if (value.isEmpty()) {
            return VM_TIER_LIGHT;
        }
        if (VM_TIER_COMPAT.equals(value)
                || VM_TIER_LIGHT.equals(value)
                || VM_TIER_STRONG.equals(value)) {
            return value;
        }
        throw new IllegalArgumentException("runtime config vmpVmTier is invalid: " + value);
    }

    private static String normalizeSha256(String raw) {
        String v = raw == null ? "" : raw.trim().replace(":", "").replace("-", "");
        if (v.length() != 64) {
            return "";
        }
        return v.toUpperCase(Locale.US);
    }

    private static String parseOptionalSha256(Map<String, String> map, String key) {
        String raw = map.get(key);
        if (raw == null || raw.trim().isEmpty()) {
            return "";
        }
        String normalized = normalizeSha256(raw);
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("runtime config " + key + " is invalid");
        }
        return normalized;
    }

    private static String normalizeBuildId(String raw) {
        String v = raw == null ? "" : raw.trim().replace("-", "").replace("_", "");
        if (v.isEmpty()) {
            return "";
        }
        if (!v.matches("[0-9A-Fa-f]{8,64}")) {
            return "";
        }
        return v.toUpperCase(Locale.US);
    }

    private static long parseLongStrict(String raw, String key) {
        if (raw == null) {
            throw new IllegalArgumentException("runtime config " + key + " is missing");
        }
        try {
            long v = Long.parseLong(raw.trim());
            if (v < 0L) {
                throw new IllegalArgumentException("runtime config " + key + " must be >= 0");
            }
            return v;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("runtime config " + key + " is invalid number", e);
        }
    }
}
