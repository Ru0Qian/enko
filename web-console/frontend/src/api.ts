export type TierLimits = {
  features?: string[];
  daily_limit?: number;
  risk_policies?: string[];
  risk_profiles?: string[];
};

export type AuthState = {
  token: string | null;
  username: string | null;
  tier: string;
  tierLimits: TierLimits | null;
  isAdmin: boolean;
};

export type Job = {
  id: string;
  status: string;
  created_at?: string;
  started_at?: string;
  finished_at?: string;
  return_code?: number | null;
  returncode?: number | null;
  progress?: number;
  progress_label?: string;
  command_preview?: string;
  input_apk?: string;
  output_apk?: string;
  output_exists?: boolean;
  report_json?: string;
  report_exists?: boolean;
  report_score?: number | null;
  report_max_score?: number | null;
  report_grade?: string | null;
  report_compiled?: unknown;
  report?: Record<string, unknown>;
  features?: Record<string, unknown>;
  resolved_tools?: Record<string, string>;
  resolved_ndk?: string;
  filtered_counts?: Record<string, number> | null;
  min_score_requested?: number;
  min_score_effective?: number;
  log?: string[];
  error?: string;
};

export type StatsPayload = {
  total_jobs?: number;
  succeeded?: number;
  failed?: number;
  running?: number;
  today_jobs?: number;
  today_succeeded?: number;
  today_running?: number;
  success_rate?: number | null;
  avg_score?: number | null;
  recent_jobs?: Job[];
};

export type HealthPayload = {
  ok: boolean;
  root?: string;
  version?: string;
  db_connected?: boolean;
  defaults?: Record<string, string>;
  defaultShellApk?: string;
  shellApkAvailable?: boolean;
  websocketAvailable?: boolean;
};

export type AdminUser = {
  username: string;
  tier: string;
  created_at?: string;
};

export type PathDiagnostic = {
  path: string;
  exists: boolean;
  kind?: string;
  is_file?: boolean;
  is_dir?: boolean;
  size?: number | null;
  writable?: boolean;
  configured?: boolean;
  usable?: boolean;
};

export type CommandDiagnostic = {
  command: string;
  ok: boolean;
  returncode?: number | null;
  version?: string;
  error?: string;
};

export type DiagnosticsPayload = {
  ok: boolean;
  timestamp: string;
  server: Record<string, unknown>;
  flags: {
    production: boolean;
    public_api_redaction: boolean;
    public_docs_enabled: boolean;
    monitor_token_configured: boolean;
    cors_origins: string[];
  };
  paths: Record<string, PathDiagnostic>;
  shell: {
    available: boolean;
    default: PathDiagnostic;
    candidates: PathDiagnostic[];
  };
  toolchain: Record<string, PathDiagnostic>;
  commands: Record<string, CommandDiagnostic>;
  database: { connected: boolean; checked?: boolean; latency_ms?: number; error?: string };
  environment: Record<string, string>;
};

export type AnalyzeMethodPayload = {
  apk_path: string;
  flutter_mode: boolean;
  selection_preset: string;
  enabled_phases: {
    extract: boolean;
    vmp: boolean;
    dex2c: boolean;
  };
};

export type MethodRecommendation = {
  level: number;
  label: string;
  score: number;
  reasons?: string[];
};

export type MethodRow = {
  spec: string;
  class: string;
  method: string;
  signature: string;
  code_bytes: number;
  package: string;
  dex: string;
  in_scope: boolean;
  best_level: number;
  best_label: string;
  best_score: number;
  best_reasons?: string[];
};

export type AnalyzeMethodsResult = {
  ok: boolean;
  total_methods: number;
  scoped_methods: number;
  include_packages: string[];
  enabled_phases: AnalyzeMethodPayload["enabled_phases"];
  selection_preset: string;
  recommended: Record<string, MethodRecommendation>;
  all_methods: MethodRow[];
  summary: {
    extract: number;
    vmp: number;
    dex2c: number;
  };
};

export type NewJobConfig = {
  inputApk: string;
  shellApk: string;
  outputApk: string;
  ndkPath: string;
  protectionMap: string;
  reportJsonPath: string;
  riskPolicy: string;
  riskProfile: string;
  commercialMode: boolean;
  flutterMode: boolean;
  signingEnabled: boolean;
  perApkKey: boolean;
  detectRoot: boolean;
  detectEmulator: boolean;
  protectDexPages: boolean;
  blockProxyVpn: boolean;
  releaseManifestEnabled: boolean;
  releaseManifestPath: string;
  signCertSha256: string;
  keystorePath: string;
  ksPass: string;
  keyAlias: string;
  keyPass: string;
  featureExtract: boolean;
  featureVmpDex: boolean;
  featureDex2c: boolean;
  featureVmpShellDex: boolean;
  featurePolymorphicShell: boolean;
  featureAiDecoy: boolean;
  extractOnDemand: boolean;
  autoProtectProfile: string;
  vmpObfuscationPreset: string;
  vmpVmTier: string;
  dex2cOllvm: boolean;
  dex2cOllvmRequired: boolean;
  dex2cOllvmClang: string;
  targetAbis: string;
  minExtract: number;
  minVmp: number;
  minDex2c: number;
  minScore: number;
};

const TOKEN_KEY = "enko_token";
const USER_KEY = "enko_user";
const TIER_KEY = "enko_tier";
const LIMITS_KEY = "enko_tier_limits";
const ADMIN_KEY = "enko_is_admin";

export function loadAuth(): AuthState {
  return {
    token: localStorage.getItem(TOKEN_KEY),
    username: localStorage.getItem(USER_KEY),
    tier: localStorage.getItem(TIER_KEY) || "free",
    tierLimits: JSON.parse(localStorage.getItem(LIMITS_KEY) || "null") as TierLimits | null,
    isAdmin: localStorage.getItem(ADMIN_KEY) === "true",
  };
}

export function saveAuth(token: string, username: string, tier = "free", tierLimits: TierLimits | null = null, isAdmin = false) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, username);
  localStorage.setItem(TIER_KEY, tier);
  localStorage.setItem(ADMIN_KEY, String(isAdmin));
  if (tierLimits) {
    localStorage.setItem(LIMITS_KEY, JSON.stringify(tierLimits));
  } else {
    localStorage.removeItem(LIMITS_KEY);
  }
}

export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  localStorage.removeItem(TIER_KEY);
  localStorage.removeItem(LIMITS_KEY);
  localStorage.removeItem(ADMIN_KEY);
}

function authHeaders(json = true): HeadersInit {
  const auth = loadAuth();
  const headers: Record<string, string> = {};
  if (json) headers["Content-Type"] = "application/json";
  if (auth.token) headers.Authorization = `Bearer ${auth.token}`;
  return headers;
}

function parseApiError(data: unknown): string {
  if (!data) return "未知错误";
  if (typeof data === "string") return data;
  if (typeof data === "object") {
    const obj = data as Record<string, unknown>;
    const detail = obj.detail || obj.error || obj.message || obj;
    if (typeof detail === "string") return detail;
    if (typeof detail === "object" && detail) {
      const detailObj = detail as Record<string, unknown>;
      if (detailObj.message) return String(detailObj.message);
    }
  }
  return "请求失败";
}

export async function apiFetch<T>(url: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: {
      ...authHeaders(!(options.body instanceof FormData)),
      ...(options.headers || {}),
    },
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401) clearAuth();
    throw new Error(parseApiError(data));
  }
  return data as T;
}

export async function login(username: string, password: string) {
  return apiFetch<{ token: string; username: string; tier: string; tier_limits: TierLimits; is_admin: boolean }>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export async function checkAuth() {
  return apiFetch<{ ok: boolean; username: string; tier: string; tier_limits: TierLimits; is_admin: boolean }>("/api/auth/check");
}

export async function getHealth() {
  return apiFetch<HealthPayload>("/api/health");
}

export async function getStats() {
  return apiFetch<StatsPayload>("/api/stats");
}

export async function listJobs() {
  return apiFetch<{ jobs: Job[] }>("/api/jobs");
}

export async function getJob(id: string) {
  return apiFetch<{ job: Job }>(`/api/jobs/${encodeURIComponent(id)}`);
}

export async function createJob(config: NewJobConfig) {
  return apiFetch<{ job: Job }>("/api/jobs", {
    method: "POST",
    body: JSON.stringify(config),
  });
}

export async function deleteJob(id: string) {
  return apiFetch<{ ok: boolean }>(`/api/jobs/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export async function getDownloadToken(id: string) {
  return apiFetch<{ token: string }>(`/api/jobs/${encodeURIComponent(id)}/download-token`, {
    method: "POST",
  });
}

export async function analyzeMethods(payload: AnalyzeMethodPayload) {
  return apiFetch<AnalyzeMethodsResult>("/api/analyze-methods", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function saveProtectionMap(content: string) {
  return apiFetch<{ ok: boolean; path: string }>("/api/save-protection-map", {
    method: "POST",
    body: JSON.stringify({ content }),
  });
}

export async function listUsers() {
  return apiFetch<{ users: AdminUser[] }>("/api/admin/users");
}

export async function createUser(username: string, password: string, tier: string) {
  return apiFetch<{ ok: boolean }>("/api/admin/create-user", {
    method: "POST",
    body: JSON.stringify({ username, password, tier }),
  });
}

export async function setUserTier(username: string, tier: string) {
  return apiFetch<{ ok: boolean }>("/api/admin/set-tier", {
    method: "POST",
    body: JSON.stringify({ username, tier }),
  });
}

export async function deleteUser(username: string) {
  return apiFetch<{ ok: boolean }>(`/api/admin/users/${encodeURIComponent(username)}`, {
    method: "DELETE",
  });
}

export async function getDiagnostics() {
  return apiFetch<DiagnosticsPayload>("/api/admin/diagnostics");
}

export async function changePassword(oldPassword: string, newPassword: string) {
  return apiFetch<{ ok: boolean }>("/api/auth/change-password", {
    method: "POST",
    body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
  });
}

export function uploadApk(file: File, onProgress?: (percent: number) => void): Promise<{ path: string; filename: string; size: number }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const form = new FormData();
    form.append("file", file);
    xhr.open("POST", "/api/upload");
    const auth = loadAuth();
    if (auth.token) xhr.setRequestHeader("Authorization", `Bearer ${auth.token}`);
    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable || !onProgress) return;
      onProgress(Math.round((event.loaded / event.total) * 100));
    };
    xhr.onload = () => {
      const data = JSON.parse(xhr.responseText || "null");
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(data);
      } else {
        reject(new Error(parseApiError(data)));
      }
    };
    xhr.onerror = () => reject(new Error("上传失败"));
    xhr.send(form);
  });
}
