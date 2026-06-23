import {
  Alert,
  AppBar,
  Avatar,
  Box,
  Button,
  Chip,
  CircularProgress,
  Collapse,
  CssBaseline,
  Dialog,
  DialogContent,
  DialogTitle,
  Divider,
  Drawer,
  FormControl,
  FormControlLabel,
  IconButton,
  LinearProgress,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  MenuItem,
  Paper,
  Select,
  Snackbar,
  Stack,
  Switch,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Tabs,
  TextField,
  ThemeProvider,
  ToggleButton,
  ToggleButtonGroup,
  Toolbar,
  Tooltip,
  Typography,
  createTheme,
} from "@mui/material";
import type { AlertColor } from "@mui/material";
import {
  AdminPanelSettingsOutlined,
  AnalyticsOutlined,
  AppRegistrationOutlined,
  AutoAwesomeOutlined,
  BarChartOutlined,
  CheckCircleOutlined,
  ChevronRight,
  DashboardOutlined,
  DeleteOutlined,
  DownloadOutlined,
  ExpandMore,
  FileUploadOutlined,
  FolderOutlined,
  KeyOutlined,
  LogoutOutlined,
  MenuOpenOutlined,
  MenuOutlined,
  PlayArrowOutlined,
  RefreshOutlined,
  ScienceOutlined,
  SearchOutlined,
  SecurityOutlined,
  SettingsOutlined,
  ShieldOutlined,
  StorageOutlined,
  VisibilityOutlined,
} from "@mui/icons-material";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";

import type {
  AdminUser,
  AnalyzeMethodsResult,
  AuthState,
  DiagnosticsPayload,
  HealthPayload,
  Job,
  MethodRecommendation,
  NewJobConfig,
  PathDiagnostic,
  StatsPayload,
} from "./api";
import {
  analyzeMethods,
  changePassword,
  checkAuth,
  clearAuth,
  createJob,
  createUser,
  deleteJob,
  deleteUser,
  getDownloadToken,
  getDiagnostics,
  getHealth,
  getJob,
  getStats,
  listJobs,
  listUsers,
  loadAuth,
  login,
  saveAuth,
  saveProtectionMap,
  setUserTier,
  uploadApk,
} from "./api";

type PageKey = "dashboard" | "new-job" | "jobs" | "reports" | "profiles" | "admin" | "ops";
type ToastState = { open: boolean; message: string; severity: AlertColor };
type PresetApplication = { id: number; patch: Partial<NewJobConfig> };
type MethodRecommendationRow = {
  spec: string;
  info: MethodRecommendation;
  className: string;
  methodName: string;
};

const pageDescriptions: Record<PageKey, string> = {
  dashboard: "查看引擎状态、任务吞吐和最近加固活动。",
  "new-job": "上传 APK，选择保护模块，并生成可追踪的加固任务。",
  jobs: "筛选、检查和下载历史加固任务。",
  reports: "载入 report.json，审查评分、等级和编译细节。",
  profiles: "套用常用保护策略，再按任务微调。",
  admin: "管理本地控制台用户和权限等级。",
  ops: "检查服务器路径、Shell APK、工具链、数据库和公开版安全开关。",
};

const drawerWidth = 264;
const collapsedWidth = 84;

const navItems: Record<PageKey, { label: string; icon: ReactNode }> = {
  dashboard: { label: "控制台", icon: <DashboardOutlined /> },
  "new-job": { label: "新建任务", icon: <ShieldOutlined /> },
  jobs: { label: "任务", icon: <FolderOutlined /> },
  reports: { label: "报告", icon: <AnalyticsOutlined /> },
  profiles: { label: "方案", icon: <AppRegistrationOutlined /> },
  admin: { label: "管理", icon: <AdminPanelSettingsOutlined /> },
  ops: { label: "运维", icon: <ScienceOutlined /> },
};

const pagePaths: Record<PageKey, string> = {
  dashboard: "/",
  "new-job": "/new-job",
  jobs: "/jobs",
  reports: "/reports",
  profiles: "/profiles",
  admin: "/admin",
  ops: "/ops",
};

const adminOnlyPages = new Set<PageKey>(["admin", "ops"]);

function pageFromPath(pathname: string): PageKey {
  const normalized = pathname.replace(/\/+$/, "") || "/";
  const match = (Object.entries(pagePaths) as Array<[PageKey, string]>)
    .find(([, path]) => path === normalized);
  return match?.[0] || "dashboard";
}

function pageForAuth(page: PageKey, isAdmin: boolean): PageKey {
  return adminOnlyPages.has(page) && !isAdmin ? "dashboard" : page;
}

const defaultConfig: NewJobConfig = {
  inputApk: "",
  shellApk: "",
  outputApk: "",
  ndkPath: "<auto-detected>",
  protectionMap: "",
  reportJsonPath: "",
  riskPolicy: "block",
  riskProfile: "strict",
  commercialMode: false,
  flutterMode: false,
  signingEnabled: false,
  perApkKey: true,
  detectRoot: true,
  detectEmulator: true,
  protectDexPages: true,
  blockProxyVpn: true,
  releaseManifestEnabled: false,
  releaseManifestPath: "release/release_manifest.json",
  signCertSha256: "",
  keystorePath: "",
  ksPass: "",
  keyAlias: "",
  keyPass: "",
  featureExtract: true,
  featureVmpDex: false,
  featureDex2c: true,
  featureVmpShellDex: false,
  featurePolymorphicShell: false,
  featureAiDecoy: false,
  extractOnDemand: true,
  autoProtectProfile: "balanced",
  vmpObfuscationPreset: "light",
  vmpVmTier: "auto",
  dex2cOllvm: true,
  dex2cOllvmRequired: false,
  dex2cOllvmClang: "",
  targetAbis: "arm64-v8a",
  minExtract: 120,
  minVmp: 30,
  minDex2c: 15,
  minScore: 80,
};

const profilePresets: Array<{
  key: string;
  title: string;
  desc: string;
  accent: "success" | "info" | "warning" | "error";
  tags: string[];
  patch: Partial<NewJobConfig>;
}> = [
  {
    key: "android-prod",
    title: "Android 生产方案",
    desc: "适合通用 APK 加固，兼顾运行时防护强度与稳定产出。",
    accent: "success",
    tags: ["阻断", "严格", "DEX2C"],
    patch: {
      flutterMode: false,
      commercialMode: false,
      riskPolicy: "block",
      riskProfile: "strict",
      featureExtract: true,
      featureVmpDex: false,
      featureDex2c: true,
      targetAbis: "arm64-v8a",
      minScore: 80,
    },
  },
  {
    key: "flutter-prod",
    title: "Flutter 生产方案",
    desc: "适合 Flutter / 混合应用，扩大 ABI 覆盖并启用 VMP 与原生化转换。",
    accent: "info",
    tags: ["Flutter", "运行时", "ARM64"],
    patch: {
      flutterMode: true,
      riskPolicy: "block",
      riskProfile: "strict",
      featureExtract: true,
      featureVmpDex: true,
      featureDex2c: true,
      targetAbis: "arm64-v8a,armeabi-v7a",
      minScore: 85,
    },
  },
  {
    key: "compat-lab",
    title: "兼容性实验室",
    desc: "适合 QA、回归测试和流水线诊断，降低运行时拦截强度。",
    accent: "warning",
    tags: ["兼容", "提示", "调试"],
    patch: {
      riskPolicy: "warn",
      riskProfile: "compat",
      detectRoot: false,
      detectEmulator: false,
      blockProxyVpn: false,
      featureVmpDex: false,
      minScore: 45,
    },
  },
  {
    key: "commercial",
    title: "商业强保护",
    desc: "启用壳自保护、多态壳与 canary 控制，适合发布前强度验证。",
    accent: "error",
    tags: ["壳保护", "诱饵", "多态"],
    patch: {
      commercialMode: true,
      riskPolicy: "block",
      riskProfile: "strict",
      featureExtract: true,
      featureVmpDex: true,
      featureDex2c: true,
      featureVmpShellDex: true,
      featurePolymorphicShell: true,
      featureAiDecoy: true,
      minScore: 90,
    },
  },
];

function policyLabel(value: string) {
  return ({ block: "阻断", degrade: "降级", warn: "提示", log: "记录", off: "关闭", exit: "退出" } as Record<string, string>)[value] || value;
}

function riskLabel(value: string) {
  return ({ strict: "严格", balanced: "均衡", compat: "兼容" } as Record<string, string>)[value] || value;
}

function statusLabel(status: string) {
  return ({ succeeded: "成功", failed: "失败", running: "运行中", queued: "排队中", idle: "空闲" } as Record<string, string>)[status] || status || "未知";
}

function statusColor(status: string): AlertColor {
  if (status === "succeeded") return "success";
  if (status === "failed") return "error";
  if (status === "running") return "info";
  if (status === "queued") return "warning";
  return "info";
}

function formatDate(value?: string) {
  if (!value) return "-";
  return new Date(value).toLocaleString("zh-CN", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function displayArtifact(value?: string) {
  if (!value) return "由服务端托管";
  const cleaned = value.replace(/\\/g, "/");
  if (cleaned.includes("://")) return "已安全托管";
  return cleaned.split("/").filter(Boolean).pop() || "已安全托管";
}

function reportScore(job: Job) {
  const nested = job.report?.score;
  return Number(job.report_score ?? (typeof nested === "number" ? nested : NaN));
}

function reportGrade(job: Job) {
  const nested = job.report?.grade;
  return job.report_grade || (typeof nested === "string" ? nested : "");
}

function featureSummary(features?: Record<string, unknown>) {
  if (!features) return "默认策略";
  const picked = [
    features.extract ? "抽取" : "",
    features.vmpDex ? "VMP" : "",
    features.dex2c ? "DEX2C" : "",
    features.vmpShellDex ? "壳保护" : "",
    features.polymorphicShell ? "多态" : "",
    features.aiDecoy ? "诱饵" : "",
  ].filter(Boolean);
  return picked.length ? picked.join(" / ") : "无";
}

function SectionCard({ title, action, children }: { title: string; action?: ReactNode; children: ReactNode }) {
  return (
    <Paper className="surface-card" variant="outlined">
      <Stack direction="row" sx={{ mb: 2, alignItems: "center", justifyContent: "space-between", gap: 2 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{title}</Typography>
        {action}
      </Stack>
      {children}
    </Paper>
  );
}

function PageMasthead({
  page,
  onNewJob,
}: {
  page: PageKey;
  onNewJob: () => void;
}) {
  const meta = navItems[page];
  return (
    <Paper className="page-masthead" variant="outlined">
      <Stack className="masthead-main" direction="row" sx={{ alignItems: "center", justifyContent: "space-between", gap: 2 }}>
        <Stack direction="row" spacing={1.5} sx={{ alignItems: "center", minWidth: 0 }}>
          <Box className="masthead-icon">{meta.icon}</Box>
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="h5" sx={{ fontWeight: 850 }}>{meta.label}</Typography>
            <Typography color="text.secondary" className="masthead-subtitle">{pageDescriptions[page]}</Typography>
          </Box>
        </Stack>
        <Stack direction="row" sx={{ alignItems: "center", gap: 1, flexWrap: "wrap", justifyContent: "flex-end" }}>
          <Chip size="small" label="本地工作区" />
          <Chip size="small" color="primary" variant="outlined" label="React · MUI" />
          {page !== "new-job" ? (
            <Button variant="contained" startIcon={<PlayArrowOutlined />} onClick={onNewJob}>
              新建任务
            </Button>
          ) : null}
        </Stack>
      </Stack>
    </Paper>
  );
}

function LoginPage({ onLogin, notify }: { onLogin: (auth: AuthState) => void; notify: (message: string, severity?: AlertColor) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit() {
    setLoading(true);
    try {
      const payload = await login(username, password);
      saveAuth(payload.token, payload.username, payload.tier, payload.tier_limits, payload.is_admin);
      onLogin({
        token: payload.token,
        username: payload.username,
        tier: payload.tier,
        tierLimits: payload.tier_limits,
        isAdmin: payload.is_admin,
      });
      notify("已进入 Enko Forge", "success");
    } catch (error) {
      notify(error instanceof Error ? error.message : "登录失败", "error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Box className="login-screen">
      <Paper className="login-panel" elevation={0}>
        <Stack spacing={3}>
          <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
            <Box className="brand-lock"><SecurityOutlined /></Box>
            <Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>Enko Forge</Typography>
              <Typography variant="body2" color="text.secondary">APK 加固控制台</Typography>
            </Box>
          </Stack>
          <Stack spacing={2}>
            <TextField label="用户名" value={username} onChange={(event) => setUsername(event.target.value)} fullWidth />
            <TextField
              label="密码"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              onKeyDown={(event) => { if (event.key === "Enter") void submit(); }}
              fullWidth
            />
          </Stack>
          <Button variant="contained" size="large" onClick={() => void submit()} disabled={loading}>
            {loading ? <CircularProgress size={20} color="inherit" /> : "登录"}
          </Button>
        </Stack>
      </Paper>
    </Box>
  );
}

function MetricCard({ label, value, icon, tone = "primary" }: { label: string; value: ReactNode; icon: ReactNode; tone?: "primary" | "success" | "warning" | "info" }) {
  return (
    <Paper className="metric-card" variant="outlined">
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between" }}>
        <Box>
          <Typography variant="body2" color="text.secondary">{label}</Typography>
          <Typography variant="h4" sx={{ mt: 0.5, fontWeight: 800 }}>{value}</Typography>
        </Box>
        <Box className={`metric-icon metric-${tone}`}>{icon}</Box>
      </Stack>
    </Paper>
  );
}

function DashboardPage({
  stats,
  health,
  jobs,
  onRefresh,
  onOpenJob,
}: {
  stats: StatsPayload | null;
  health: HealthPayload | null;
  jobs: Job[];
  onRefresh: () => void;
  onOpenJob: (job: Job) => void;
}) {
  const successRate = stats?.success_rate == null ? 0 : Math.round(stats.success_rate * 100);
  const avgScore = stats?.avg_score == null ? "-" : Number(stats.avg_score).toFixed(1);
  const runningJobs = jobs.filter((job) => job.status === "running").length;
  const queuedJobs = jobs.filter((job) => job.status === "queued").length;
  const failedJobs = stats?.failed || jobs.filter((job) => job.status === "failed").length;
  return (
    <Stack spacing={2.5}>
      <Box className="metrics-grid">
        <MetricCard label="总任务" value={stats?.total_jobs || 0} icon={<FolderOutlined />} />
        <MetricCard label="成功任务" value={stats?.succeeded || 0} icon={<CheckCircleOutlined />} tone="success" />
        <MetricCard label="平均评分" value={avgScore} icon={<BarChartOutlined />} tone="info" />
        <MetricCard label="成功率" value={`${successRate}%`} icon={<AutoAwesomeOutlined />} tone="warning" />
      </Box>
      <Paper className="signal-strip" variant="outlined">
        <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", gap: 2, flexWrap: "wrap" }}>
          <Stack direction="row" sx={{ alignItems: "center", gap: 1, flexWrap: "wrap" }}>
            <Typography sx={{ fontWeight: 800 }}>任务分流</Typography>
            <Chip size="small" color={failedJobs ? "error" : "default"} label={`失败 ${failedJobs}`} />
            <Chip size="small" color={runningJobs ? "info" : "default"} label={`运行中 ${runningJobs}`} />
            <Chip size="small" color={queuedJobs ? "warning" : "default"} label={`排队 ${queuedJobs}`} />
          </Stack>
          <Typography variant="body2" color="text.secondary">
            今日 {stats?.today_jobs || 0} 个任务，{stats?.today_succeeded || 0} 个已完成
          </Typography>
        </Stack>
      </Paper>
      <Box className="dashboard-grid">
        <SectionCard
          title="最近任务"
          action={<Button startIcon={<RefreshOutlined />} onClick={onRefresh}>刷新</Button>}
        >
          <JobsTable jobs={jobs.slice(0, 7)} compact onOpenJob={onOpenJob} />
        </SectionCard>
        <Stack spacing={2}>
          <SectionCard title="引擎状态">
            <Stack spacing={1.5}>
              <Alert severity={health?.ok ? "success" : "warning"} variant="outlined">
                {health?.ok ? "本地引擎在线" : "等待引擎状态"}
              </Alert>
              <Stack spacing={1}>
                <Stack direction="row" sx={{ justifyContent: "space-between" }}><Typography color="text.secondary">Shell APK</Typography><Chip size="small" color={health?.shellApkAvailable ? "success" : "default"} label={health?.shellApkAvailable ? "可用" : "缺失"} /></Stack>
                <Stack direction="row" sx={{ justifyContent: "space-between" }}><Typography color="text.secondary">WebSocket</Typography><Chip size="small" label={health?.websocketAvailable ? "可用" : "轮询"} /></Stack>
                <Typography variant="caption" color="text.secondary">构建环境</Typography>
                <Typography className="mono-line">{health?.defaults?.ndk ? "已配置" : "自动检测"}</Typography>
              </Stack>
            </Stack>
          </SectionCard>
          <SectionCard title="今日概览">
            <Stack direction="row" sx={{ gap: 4 }}>
              <Box><Typography variant="body2" color="text.secondary">任务</Typography><Typography variant="h5" sx={{ fontWeight: 800 }}>{stats?.today_jobs || 0}</Typography></Box>
              <Box><Typography variant="body2" color="text.secondary">运行中</Typography><Typography variant="h5" sx={{ fontWeight: 800 }}>{stats?.today_running || 0}</Typography></Box>
            </Stack>
          </SectionCard>
        </Stack>
      </Box>
    </Stack>
  );
}

function FileDropzone({
  inputApk,
  uploading,
  uploadPercent,
  onFile,
}: {
  inputApk: string;
  uploading: boolean;
  uploadPercent: number;
  onFile: (file: File) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);

  return (
    <Box
      className="file-dropzone"
      onClick={() => inputRef.current?.click()}
      onDragOver={(event) => event.preventDefault()}
      onDrop={(event) => {
        event.preventDefault();
        const file = event.dataTransfer.files.item(0);
        if (file) onFile(file);
      }}
    >
      <input
        ref={inputRef}
        hidden
        type="file"
        accept=".apk"
        onChange={(event) => {
          const file = event.target.files?.item(0);
          if (file) onFile(file);
          event.target.value = "";
        }}
      />
      <FileUploadOutlined color="primary" />
      <Typography sx={{ fontWeight: 700 }}>拖入 APK，或点击选择文件</Typography>
      <Typography variant="body2" color="text.secondary">上传后由服务端安全托管。</Typography>
      {uploading ? <LinearProgress variant="determinate" value={uploadPercent} sx={{ width: "100%", mt: 1 }} /> : null}
      {inputApk ? <Typography className="mono-line" sx={{ mt: 1 }}>{displayArtifact(inputApk)}</Typography> : null}
    </Box>
  );
}

function MethodAnalysisPanel({
  config,
  patch,
  notify,
}: {
  config: NewJobConfig;
  patch: (next: Partial<NewJobConfig>) => void;
  notify: (message: string, severity?: AlertColor) => void;
}) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [analysis, setAnalysis] = useState<AnalyzeMethodsResult | null>(null);
  const [selected, setSelected] = useState<Record<string, number>>({});
  const [preset, setPreset] = useState("balanced");

  const recommendationRows = useMemo<MethodRecommendationRow[]>(() => {
    if (!analysis) return [];
    return Object.entries(analysis.recommended || {})
      .map(([spec, info]) => {
        const method = analysis.all_methods.find((item) => item.spec === spec);
        return { spec, info, className: method?.class || "", methodName: method?.method || "" };
      })
      .sort((a, b) => b.info.score - a.info.score);
  }, [analysis]);

  const selectedCount = Object.values(selected).filter((level) => level > 0).length;

  async function runAnalysis() {
    if (!config.inputApk) {
      notify("请先上传 APK 再执行方法分析", "warning");
      return;
    }
    setLoading(true);
    try {
      const result = await analyzeMethods({
        apk_path: config.inputApk,
        flutter_mode: config.flutterMode,
        selection_preset: preset,
        enabled_phases: {
          extract: config.featureExtract,
          vmp: config.featureVmpDex,
          dex2c: config.featureDex2c,
        },
      });
      const nextSelected: Record<string, number> = {};
      Object.entries(result.recommended || {}).forEach(([spec, info]) => {
        nextSelected[spec] = info.level;
      });
      setAnalysis(result);
      setSelected(nextSelected);
      notify(`分析完成：共 ${result.total_methods} 个方法，推荐 ${Object.keys(result.recommended || {}).length} 个`, "success");
    } catch (error) {
      notify(error instanceof Error ? error.message : "方法分析失败", "error");
    } finally {
      setLoading(false);
    }
  }

  async function saveMap() {
    const lines = Object.entries(selected)
      .filter(([, level]) => level > 0)
      .sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0]))
      .map(([spec, level]) => `${spec} ${level}`);
    if (!lines.length) {
      notify("尚未选择任何方法", "warning");
      return;
    }
    setSaving(true);
    try {
      const result = await saveProtectionMap(`${lines.join("\n")}\n`);
      patch({ protectionMap: result.path });
      notify(`已为 ${lines.length} 个方法生成保护映射`, "success");
    } catch (error) {
      notify(error instanceof Error ? error.message : "保存保护映射失败", "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <SectionCard
      title="智能方法分析"
      action={
        <Stack direction="row" spacing={1}>
          <Select size="small" value={preset} onChange={(event) => setPreset(event.target.value)} sx={{ minWidth: 132 }}>
            <MenuItem value="compat">兼容</MenuItem>
            <MenuItem value="balanced">均衡</MenuItem>
            <MenuItem value="strong">强保护</MenuItem>
          </Select>
          <Button startIcon={<ScienceOutlined />} onClick={() => void runAnalysis()} disabled={loading}>
            分析
          </Button>
          <Button variant="contained" onClick={() => void saveMap()} disabled={!selectedCount || saving}>
            保存映射
          </Button>
        </Stack>
      }
    >
      {!analysis ? (
        <Box className="empty-state">
          <ScienceOutlined />
          <Typography sx={{ fontWeight: 700 }}>尚未分析</Typography>
          <Typography variant="body2" color="text.secondary">上传 APK 后可自动推荐 Extract、VMP 和 DEX2C 候选方法。</Typography>
        </Box>
      ) : (
        <Stack spacing={2}>
          <Box className="mini-metrics">
            <MetricCard label="总方法" value={analysis.total_methods} icon={<ScienceOutlined />} />
            <MetricCard label="业务范围" value={analysis.scoped_methods} icon={<SearchOutlined />} tone="info" />
            <MetricCard label="推荐方法" value={recommendationRows.length} icon={<AutoAwesomeOutlined />} tone="warning" />
            <MetricCard label="已选择" value={selectedCount} icon={<CheckCircleOutlined />} tone="success" />
          </Box>
          <Stack direction="row" sx={{ gap: 1, flexWrap: "wrap" }}>
            {(analysis.include_packages || []).slice(0, 8).map((pkg) => <Chip key={pkg} label={pkg} size="small" />)}
          </Stack>
          <Paper variant="outlined" className="table-shell">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>方法</TableCell>
                  <TableCell width={90}>评分</TableCell>
                  <TableCell width={150}>级别</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {recommendationRows.slice(0, 12).map((row) => (
                  <TableRow key={row.spec}>
                    <TableCell>
                      <Typography className="mono-line">{row.className ? `${row.className}->${row.methodName}` : row.spec}</Typography>
                      <Typography variant="caption" color="text.secondary" className="mono-line">{row.spec}</Typography>
                    </TableCell>
                    <TableCell><Chip size="small" color="info" label={row.info.score} /></TableCell>
                    <TableCell>
                      <Select
                        size="small"
                        value={String(selected[row.spec] ?? row.info.level)}
                        onChange={(event) => setSelected((current) => ({ ...current, [row.spec]: Number(event.target.value) }))}
                        fullWidth
                      >
                        <MenuItem value="0">无保护</MenuItem>
                        <MenuItem value="1">Extract</MenuItem>
                        <MenuItem value="2">VMP</MenuItem>
                        <MenuItem value="3">DEX2C</MenuItem>
                      </Select>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>
          {config.protectionMap ? <Alert severity="success" variant="outlined">保护映射已生成并由服务端安全托管。</Alert> : null}
        </Stack>
      )}
    </SectionCard>
  );
}

function NewJobPage({
  health,
  preset,
  onCreated,
  notify,
}: {
  health: HealthPayload | null;
  preset: PresetApplication | null;
  onCreated: (job: Job) => void;
  notify: (message: string, severity?: AlertColor) => void;
}) {
  const [config, setConfig] = useState<NewJobConfig>(() => ({ ...defaultConfig }));
  const [uploading, setUploading] = useState(false);
  const [uploadPercent, setUploadPercent] = useState(0);
  const [creating, setCreating] = useState(false);
  const [targetOpen, setTargetOpen] = useState(false);
  const [buildOpen, setBuildOpen] = useState(false);

  function patch(next: Partial<NewJobConfig>) {
    setConfig((current) => ({ ...current, ...next }));
  }

  useEffect(() => {
    if (!health) return;
    setConfig((current) => ({
      ...current,
      ndkPath: current.ndkPath === "<auto-detected>" ? (health.defaults?.ndk || "<auto-detected>") : current.ndkPath,
    }));
  }, [health]);

  useEffect(() => {
    if (!preset) return;
    setConfig((current) => ({ ...current, ...preset.patch }));
    notify("已将方案应用到新建任务表单", "success");
  }, [preset]);

  async function handleFile(file: File) {
    setUploading(true);
    setUploadPercent(0);
    try {
      const result = await uploadApk(file, setUploadPercent);
      patch({ inputApk: result.path });
      notify(`已上传 ${result.filename}`, "success");
    } catch (error) {
      notify(error instanceof Error ? error.message : "上传失败", "error");
    } finally {
      setUploading(false);
    }
  }

  async function submitJob() {
    if (!config.inputApk) {
      notify("请先上传 APK", "warning");
      return;
    }
    setCreating(true);
    try {
      const result = await createJob(config);
      notify(`任务已创建：${result.job.id}`, "success");
      onCreated(result.job);
    } catch (error) {
      notify(error instanceof Error ? error.message : "创建任务失败", "error");
    } finally {
      setCreating(false);
    }
  }

  const featureRows = [
    { key: "featureExtract", title: "方法抽取", desc: "按需恢复敏感方法。", color: "success" },
    { key: "featureVmpDex", title: "VMP DEX", desc: "将方法迁移到自定义 VM 层。", color: "info" },
    { key: "featureDex2c", title: "DEX2C", desc: "将 Java 方法转换为 native 代码。", color: "warning" },
    { key: "featureVmpShellDex", title: "壳自保护", desc: "保护启动链路和壳校验流程。", color: "primary" },
    { key: "featurePolymorphicShell", title: "多态壳", desc: "每次构建生成不同壳结构。", color: "secondary" },
    { key: "featureAiDecoy", title: "AI 诱饵", desc: "注入 canary token 和诱饵信号。", color: "error" },
  ] as const;

  return (
    <Box className="job-workbench">
      <Stack className="job-main" spacing={2.5}>
        <Box className="compose-grid">
          <SectionCard title="源 APK" action={config.inputApk ? <Chip size="small" color="success" label="就绪" /> : <Chip size="small" label="等待上传" />}>
            <FileDropzone inputApk={config.inputApk} uploading={uploading} uploadPercent={uploadPercent} onFile={(file) => void handleFile(file)} />
          </SectionCard>
          <SectionCard title="配置方案">
            <Stack spacing={1}>
              {profilePresets.slice(0, 3).map((item) => (
                <Button key={item.key} className="profile-button" onClick={() => patch(item.patch)} endIcon={<ChevronRight />}>
                  <Box sx={{ textAlign: "left" }}>
                    <Typography sx={{ fontWeight: 700 }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Box>
                </Button>
              ))}
            </Stack>
          </SectionCard>
        </Box>

        <SectionCard title="保护模块">
          <Box className="feature-grid">
            {featureRows.map((item) => (
              <Paper key={item.key} variant="outlined" className="option-card">
                <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "flex-start", gap: 2 }}>
                  <Box>
                    <Chip size="small" color={item.color} label={item.title} />
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{item.desc}</Typography>
                  </Box>
                  <Switch checked={Boolean(config[item.key])} onChange={(event) => patch({ [item.key]: event.target.checked } as Partial<NewJobConfig>)} />
                </Stack>
              </Paper>
            ))}
          </Box>
          <Box className="two-column" sx={{ mt: 2 }}>
            <Paper variant="outlined" className="option-card">
              <Typography sx={{ mb: 1, fontWeight: 700 }}>VMP 运行时</Typography>
              <Stack direction="row" sx={{ gap: 1, flexWrap: "wrap" }}>
                <Select size="small" value={config.vmpObfuscationPreset} onChange={(event) => patch({ vmpObfuscationPreset: event.target.value })}>
                  <MenuItem value="light">轻量</MenuItem>
                  <MenuItem value="medium">中等</MenuItem>
                  <MenuItem value="stable">稳定</MenuItem>
                </Select>
                <Select size="small" value={config.vmpVmTier} onChange={(event) => patch({ vmpVmTier: event.target.value })}>
                  <MenuItem value="auto">自动</MenuItem>
                  <MenuItem value="compat">兼容</MenuItem>
                  <MenuItem value="light">轻量</MenuItem>
                  <MenuItem value="strong">强保护</MenuItem>
                </Select>
                <FormControlLabel control={<Switch checked={config.extractOnDemand} onChange={(event) => patch({ extractOnDemand: event.target.checked })} />} label="按需恢复" />
              </Stack>
            </Paper>
            <Paper variant="outlined" className="option-card">
              <Typography sx={{ mb: 1, fontWeight: 700 }}>DEX2C OLLVM</Typography>
              <Stack spacing={1}>
                <Stack direction="row" sx={{ gap: 2, flexWrap: "wrap" }}>
                  <FormControlLabel control={<Switch checked={config.dex2cOllvm} onChange={(event) => patch({ dex2cOllvm: event.target.checked })} />} label="启用" />
                  <FormControlLabel control={<Switch checked={config.dex2cOllvmRequired} onChange={(event) => patch({ dex2cOllvmRequired: event.target.checked })} />} label="必须成功" />
                </Stack>
                <Chip size="small" label="工具链由服务端托管" sx={{ alignSelf: "flex-start" }} />
              </Stack>
            </Paper>
          </Box>
        </SectionCard>

        <SectionCard title="运行时风险策略">
          <Box className="risk-grid">
            <Stack spacing={1.5}>
              {[
                ["detectRoot", "Root 检测", "识别 root 或越狱设备。"],
                ["detectEmulator", "模拟器检测", "识别模拟器和云手机运行环境。"],
                ["protectDexPages", "DEX 页封存", "加载后保护内存中的 DEX 页。"],
                ["blockProxyVpn", "代理 / VPN 拦截", "降低流量劫持风险。"],
              ].map(([key, title, desc]) => (
                <Paper key={key} variant="outlined" className="setting-row">
                  <Box>
                    <Typography sx={{ fontWeight: 700 }}>{title}</Typography>
                    <Typography variant="body2" color="text.secondary">{desc}</Typography>
                  </Box>
                  <Switch checked={Boolean(config[key as keyof NewJobConfig])} onChange={(event) => patch({ [key]: event.target.checked } as Partial<NewJobConfig>)} />
                </Paper>
              ))}
            </Stack>
            <Stack spacing={2}>
              <Box>
                <Typography sx={{ mb: 1, fontWeight: 700 }}>处理策略</Typography>
                <ToggleButtonGroup
                  value={config.riskPolicy}
                  exclusive
                  fullWidth
                  onChange={(_event, value) => value && patch({ riskPolicy: value })}
                >
                  <ToggleButton value="block">阻断</ToggleButton>
                  <ToggleButton value="degrade">降级</ToggleButton>
                  <ToggleButton value="warn">提示</ToggleButton>
                  <ToggleButton value="log">记录</ToggleButton>
                  <ToggleButton value="off">关闭</ToggleButton>
                </ToggleButtonGroup>
              </Box>
              <Box>
                <Typography sx={{ mb: 1, fontWeight: 700 }}>风险档位</Typography>
                <ToggleButtonGroup
                  value={config.riskProfile}
                  exclusive
                  fullWidth
                  onChange={(_event, value) => value && patch({ riskProfile: value })}
                >
                  <ToggleButton value="compat">兼容</ToggleButton>
                  <ToggleButton value="balanced">均衡</ToggleButton>
                  <ToggleButton value="strict">严格</ToggleButton>
                </ToggleButtonGroup>
              </Box>
              <Alert severity={config.riskProfile === "strict" ? "warning" : "info"} variant="outlined">
                {config.riskProfile === "strict" ? "严格档位可能终止高置信风险进程。" : "兼容和均衡档位会降低拦截强度，以覆盖更多设备。"}
              </Alert>
            </Stack>
          </Box>
        </SectionCard>

        <MethodAnalysisPanel config={config} patch={patch} notify={notify} />

        <SectionCard title="高级构建设置">
          <Stack spacing={1}>
            <Button className="accordion-button" onClick={() => setTargetOpen((value) => !value)} endIcon={<ExpandMore />}>目标平台与阈值</Button>
            <Collapse in={targetOpen}>
              <Stack spacing={2} sx={{ pt: 1 }}>
                <ToggleButtonGroup value={config.flutterMode ? "flutter" : "android"} exclusive onChange={(_event, value) => value && patch({ flutterMode: value === "flutter" })}>
                  <ToggleButton value="android">Android 原生</ToggleButton>
                  <ToggleButton value="flutter">Flutter 运行时</ToggleButton>
                </ToggleButtonGroup>
                <TextField size="small" label="目标 ABI" value={config.targetAbis} onChange={(event) => patch({ targetAbis: event.target.value })} />
                <Box className="four-column">
                  {[
                    ["minExtract", "最少 Extract"],
                    ["minVmp", "最少 VMP"],
                    ["minDex2c", "最少 DEX2C"],
                    ["minScore", "最低评分"],
                  ].map(([key, label]) => (
                    <TextField key={key} size="small" label={label} type="number" value={Number(config[key as keyof NewJobConfig])} onChange={(event) => patch({ [key]: Number(event.target.value || 0) } as Partial<NewJobConfig>)} />
                  ))}
                </Box>
              </Stack>
            </Collapse>
            <Button className="accordion-button" onClick={() => setBuildOpen((value) => !value)} endIcon={<ExpandMore />}>构建、签名与产物</Button>
            <Collapse in={buildOpen}>
              <Box className="two-column" sx={{ pt: 1 }}>
                <TextField size="small" label="Shell APK" value={health?.shellApkAvailable ? "已配置" : "等待服务端配置"} disabled />
                <TextField size="small" label="输出 APK" value="由服务端自动生成" disabled />
                <TextField size="small" label="构建环境" value={config.ndkPath && config.ndkPath !== "<auto-detected>" ? "已配置" : "自动检测"} disabled />
                <TextField size="small" label="保护映射" value={config.protectionMap ? "已生成" : "未生成"} disabled />
                <TextField size="small" label="原证书 SHA-256" value={config.signCertSha256} onChange={(event) => patch({ signCertSha256: event.target.value })} />
                <FormControlLabel control={<Switch checked={false} disabled />} label="托管签名暂未开放" />
              </Box>
            </Collapse>
          </Stack>
        </SectionCard>
      </Stack>

      <Stack className="job-rail" spacing={2}>
        <SectionCard title="运行摘要">
          <Stack spacing={1.5}>
            <Stack direction="row" sx={{ gap: 1, flexWrap: "wrap" }}>
              <Chip label={config.flutterMode ? "Flutter" : "Android"} color="success" size="small" />
              <Chip label={`${policyLabel(config.riskPolicy)} / ${riskLabel(config.riskProfile)}`} color="info" size="small" />
              <Chip label={config.targetAbis || "未选择 ABI"} size="small" />
            </Stack>
            <Divider />
            <Stack spacing={1}>
              <Stack direction="row" sx={{ justifyContent: "space-between" }}><Typography>方法抽取</Typography><CheckCircleOutlined color={config.featureExtract ? "success" : "disabled"} /></Stack>
              <Stack direction="row" sx={{ justifyContent: "space-between" }}><Typography>VMP DEX</Typography><CheckCircleOutlined color={config.featureVmpDex ? "success" : "disabled"} /></Stack>
              <Stack direction="row" sx={{ justifyContent: "space-between" }}><Typography>DEX2C</Typography><CheckCircleOutlined color={config.featureDex2c ? "success" : "disabled"} /></Stack>
              <Stack direction="row" sx={{ justifyContent: "space-between" }}><Typography>DEX 页封存</Typography><CheckCircleOutlined color={config.protectDexPages ? "success" : "disabled"} /></Stack>
            </Stack>
            <Button variant="contained" size="large" startIcon={<PlayArrowOutlined />} onClick={() => void submitJob()} disabled={creating}>
              {creating ? "启动中..." : "开始加固"}
            </Button>
          </Stack>
        </SectionCard>
        <SectionCard title="公开版安全策略">
          <Alert severity="info" variant="outlined">
            命令行、服务端路径和构建日志不会在公开控制台展示。产物与报告通过受控下载接口访问。
          </Alert>
        </SectionCard>
      </Stack>
    </Box>
  );
}

function JobsTable({
  jobs,
  compact = false,
  onOpenJob,
  onDeleteJob,
}: {
  jobs: Job[];
  compact?: boolean;
  onOpenJob: (job: Job) => void;
  onDeleteJob?: (job: Job) => void;
}) {
  if (!jobs.length) {
    return (
      <Box className="empty-state">
        <FolderOutlined />
        <Typography sx={{ fontWeight: 700 }}>暂无任务</Typography>
      </Box>
    );
  }

  return (
    <Paper variant="outlined" className="table-shell">
      <Table size={compact ? "small" : "medium"}>
        <TableHead>
          <TableRow>
            <TableCell>任务</TableCell>
            <TableCell>状态</TableCell>
            <TableCell className="hide-sm">功能</TableCell>
            <TableCell>评分</TableCell>
            <TableCell className="hide-md">创建时间</TableCell>
            <TableCell align="right">操作</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {jobs.map((job) => {
            const score = reportScore(job);
            const grade = reportGrade(job);
            return (
              <TableRow key={job.id} hover className="clickable-row" onClick={() => onOpenJob(job)}>
                <TableCell><Typography className="mono-line">{job.id}</Typography></TableCell>
                <TableCell><Chip size="small" color={statusColor(job.status)} label={statusLabel(job.status)} /></TableCell>
                <TableCell className="hide-sm"><Typography variant="body2" color="text.secondary">{featureSummary(job.features)}</Typography></TableCell>
                <TableCell>{Number.isFinite(score) ? <Stack direction="row" sx={{ gap: 1, alignItems: "center" }}><Typography sx={{ fontWeight: 700 }}>{score}</Typography>{grade ? <Chip size="small" label={grade} /> : null}</Stack> : "-"}</TableCell>
                <TableCell className="hide-md">{formatDate(job.created_at)}</TableCell>
                <TableCell align="right" onClick={(event) => event.stopPropagation()}>
                  <Tooltip title="查看"><IconButton size="small" onClick={() => onOpenJob(job)}><VisibilityOutlined fontSize="small" /></IconButton></Tooltip>
                  {onDeleteJob && ["succeeded", "failed"].includes(job.status) ? (
                    <Tooltip title="删除"><IconButton size="small" color="error" onClick={() => onDeleteJob(job)}><DeleteOutlined fontSize="small" /></IconButton></Tooltip>
                  ) : null}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </Paper>
  );
}

function JobDetailDrawer({
  job,
  open,
  onClose,
  onChanged,
  notify,
}: {
  job: Job | null;
  open: boolean;
  onClose: () => void;
  onChanged: () => void;
  notify: (message: string, severity?: AlertColor) => void;
}) {
  const [detail, setDetail] = useState<Job | null>(job);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState(0);

  async function refresh() {
    if (!job?.id) return;
    setLoading(true);
    try {
      const result = await getJob(job.id);
      setDetail(result.job);
      if (["succeeded", "failed"].includes(result.job.status)) onChanged();
    } catch (error) {
      notify(error instanceof Error ? error.message : "任务详情加载失败", "error");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    setDetail(job);
    if (open && job?.id) void refresh();
  }, [open, job?.id]);

  useEffect(() => {
    if (!open || !detail || !["running", "queued"].includes(detail.status)) return undefined;
    const timer = window.setInterval(() => void refresh(), 4000);
    return () => window.clearInterval(timer);
  }, [open, detail?.id, detail?.status]);

  async function download() {
    if (!detail?.id) return;
    const tokenPayload = await getDownloadToken(detail.id).catch(() => null);
    let url = `/api/jobs/${encodeURIComponent(detail.id)}/download`;
    if (tokenPayload?.token) url += `?dl_token=${encodeURIComponent(tokenPayload.token)}`;
    const link = document.createElement("a");
    link.href = url;
    link.download = `${detail.id}-hardened.apk`;
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  const safe = detail || job;
  const score = safe ? reportScore(safe) : NaN;
  const grade = safe ? reportGrade(safe) : "";

  return (
    <Drawer anchor="right" open={open} onClose={onClose} sx={{ "& .MuiDrawer-paper": { width: { xs: "100%", sm: 740 }, p: 0 } }}>
      {!safe ? (
        <Box className="empty-state"><Typography>未选择任务</Typography></Box>
      ) : (
        <Stack spacing={2} sx={{ p: 3 }}>
          <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "center", gap: 2 }}>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 800 }}>任务 {safe.id}</Typography>
              <Typography variant="body2" color="text.secondary">{formatDate(safe.created_at)}</Typography>
            </Box>
            <Stack direction="row" sx={{ gap: 1 }}>
              <Button startIcon={<RefreshOutlined />} onClick={() => void refresh()} disabled={loading}>刷新</Button>
              <Button variant="contained" startIcon={<DownloadOutlined />} disabled={!safe.output_exists && safe.status !== "succeeded"} onClick={() => void download()}>下载</Button>
            </Stack>
          </Stack>
          <Box className="metrics-grid compact">
            <MetricCard label="状态" value={statusLabel(safe.status)} icon={<CheckCircleOutlined />} tone={safe.status === "failed" ? "warning" : "success"} />
            <MetricCard label="进度" value={`${safe.progress || 0}%`} icon={<RefreshOutlined />} tone="info" />
            <MetricCard label="评分" value={Number.isFinite(score) ? `${score}${grade ? ` ${grade}` : ""}` : "-"} icon={<BarChartOutlined />} tone="warning" />
          </Box>
          {safe.progress ? <LinearProgress variant="determinate" value={safe.progress} color={safe.status === "failed" ? "error" : "primary"} /> : null}
          {safe.error ? <Alert severity="error" variant="outlined">{safe.error}</Alert> : null}
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Stack spacing={1.5}>
              <Stack><Typography variant="caption" color="text.secondary">输入 APK</Typography><Typography className="mono-line">{displayArtifact(safe.input_apk)}</Typography></Stack>
              <Stack><Typography variant="caption" color="text.secondary">输出 APK</Typography><Typography className="mono-line">{safe.output_exists ? displayArtifact(safe.output_apk) : "产物生成后可下载"}</Typography></Stack>
              <Stack><Typography variant="caption" color="text.secondary">报告</Typography><Typography className="mono-line">{safe.report_exists ? "已生成" : "等待生成"}</Typography></Stack>
              <Stack direction="row" sx={{ gap: 1, flexWrap: "wrap" }}>
                <Chip label={featureSummary(safe.features)} />
                <Chip label={`返回码 ${safe.returncode ?? safe.return_code ?? "-"}`} />
              </Stack>
            </Stack>
          </Paper>
          <Paper variant="outlined">
            <Tabs value={tab} onChange={(_event, value) => setTab(value)} sx={{ borderBottom: 1, borderColor: "divider", px: 1 }}>
              <Tab label="报告" />
              <Tab label="安全说明" />
            </Tabs>
            <Box sx={{ p: 2 }}>
              {tab === 0 ? <pre className="code-panel report-json">{JSON.stringify(safe.report || {}, null, 2)}</pre> : null}
              {tab === 1 ? <Alert severity="info" variant="outlined">公开版不会展示服务端命令行、绝对路径或构建日志。请通过任务状态、报告评分和下载结果判断任务产出。</Alert> : null}
            </Box>
          </Paper>
        </Stack>
      )}
    </Drawer>
  );
}

function JobsPage({
  jobs,
  onRefresh,
  onOpenJob,
  onDeleteJob,
}: {
  jobs: Job[];
  onRefresh: () => void;
  onOpenJob: (job: Job) => void;
  onDeleteJob: (job: Job) => void;
}) {
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const rows = jobs.filter((job) => {
    if (status !== "all" && job.status !== status) return false;
    if (!search.trim()) return true;
    const text = [job.id, job.status, displayArtifact(job.input_apk), displayArtifact(job.output_apk), featureSummary(job.features)].filter(Boolean).join(" ").toLowerCase();
    return text.includes(search.trim().toLowerCase());
  });

  return (
    <SectionCard
      title="任务"
      action={<Button startIcon={<RefreshOutlined />} onClick={onRefresh}>刷新</Button>}
    >
      <Stack spacing={2}>
        <Stack direction="row" sx={{ gap: 1.5, flexWrap: "wrap" }}>
          <TextField
            size="small"
            placeholder="搜索任务或产物"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            sx={{ width: { xs: "100%", sm: 340 } }}
          />
          <FormControl size="small" sx={{ minWidth: 160 }}>
            <Select value={status} onChange={(event) => setStatus(event.target.value)}>
              <MenuItem value="all">全部状态</MenuItem>
              <MenuItem value="queued">排队中</MenuItem>
              <MenuItem value="running">运行中</MenuItem>
              <MenuItem value="succeeded">成功</MenuItem>
              <MenuItem value="failed">失败</MenuItem>
            </Select>
          </FormControl>
        </Stack>
        <JobsTable jobs={rows} onOpenJob={onOpenJob} onDeleteJob={onDeleteJob} />
      </Stack>
    </SectionCard>
  );
}

function ReportsPage({ jobs, onOpenJob, notify }: { jobs: Job[]; onOpenJob: (job: Job) => void; notify: (message: string, severity?: AlertColor) => void }) {
  const [report, setReport] = useState<Record<string, unknown> | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const scoredJobs = jobs.filter((job) => Number.isFinite(reportScore(job))).slice(0, 8);
  const score = Number(report?.score || 0);

  async function loadReport(file: File) {
    try {
      setReport(JSON.parse(await file.text()) as Record<string, unknown>);
      notify("报告已载入", "success");
    } catch {
      notify("报告解析失败", "error");
    }
  }

  return (
    <Box className="reports-grid">
      <Stack spacing={2}>
        <SectionCard title="载入 report.json">
          <Box className="file-dropzone" onClick={() => fileRef.current?.click()}>
            <input ref={fileRef} hidden type="file" accept=".json" onChange={(event) => { const file = event.target.files?.item(0); if (file) void loadReport(file); }} />
            <AnalyticsOutlined color="primary" />
            <Typography sx={{ fontWeight: 700 }}>选择报告 JSON</Typography>
            <Typography variant="body2" color="text.secondary">查看评分、等级和编译详情。</Typography>
          </Box>
        </SectionCard>
        <SectionCard title="最近有评分的任务">
          <List dense disablePadding>
            {scoredJobs.length ? scoredJobs.map((job) => (
              <ListItemButton key={job.id} onClick={() => onOpenJob(job)}>
                <ListItemText primary={<Typography className="mono-line">{job.id}</Typography>} secondary={`${reportScore(job)} / ${reportGrade(job) || "-"}`} />
              </ListItemButton>
            )) : <Typography color="text.secondary">暂无有评分任务。</Typography>}
          </List>
        </SectionCard>
      </Stack>
      <SectionCard title="报告概览">
        {report ? (
          <Stack spacing={2}>
            <Box className="score-ring"><Typography variant="h3" sx={{ fontWeight: 800 }}>{score}</Typography><Typography color="text.secondary">评分</Typography></Box>
            <Stack direction="row" sx={{ gap: 1, flexWrap: "wrap" }}>
              <Chip color="success" label={`等级 ${String(report.grade || "-")}`} />
              <Chip label={`${String(report.risk_policy || "-")} / ${String(report.risk_profile || "-")}`} />
              <Chip label={String(report.compiled ? "已编译" : "原始")} />
            </Stack>
            <pre className="code-panel report-json">{JSON.stringify(report, null, 2)}</pre>
          </Stack>
        ) : (
          <Box className="empty-state"><Typography sx={{ fontWeight: 700 }}>尚未载入报告</Typography></Box>
        )}
      </SectionCard>
    </Box>
  );
}

function ProfilesPage({ onApply }: { onApply: (patch: Partial<NewJobConfig>) => void }) {
  return (
    <Stack spacing={2}>
      <Box className="profiles-grid">
        {profilePresets.map((preset) => (
          <Paper key={preset.key} variant="outlined" className="profile-card">
            <Stack spacing={2} sx={{ height: "100%" }}>
              <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "center" }}>
                <Typography variant="h6" sx={{ fontWeight: 800 }}>{preset.title}</Typography>
                <Chip size="small" color={preset.accent} label={preset.tags[0]} />
              </Stack>
              <Typography color="text.secondary">{preset.desc}</Typography>
              <Stack direction="row" sx={{ gap: 1, flexWrap: "wrap" }}>
                {preset.tags.map((tag) => <Chip key={tag} label={tag} size="small" variant="outlined" />)}
              </Stack>
              <Box sx={{ flex: 1 }} />
              <Button variant="contained" startIcon={<SettingsOutlined />} onClick={() => onApply(preset.patch)}>应用到新建任务</Button>
            </Stack>
          </Paper>
        ))}
      </Box>
      <Alert severity="info" variant="outlined">配置方案会直接写入新建任务表单，提交前仍可继续微调。</Alert>
    </Stack>
  );
}

function AdminPage({ notify }: { notify: (message: string, severity?: AlertColor) => void }) {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [tier, setTier] = useState("free");

  async function refresh() {
    setLoading(true);
    try {
      const result = await listUsers();
      setUsers(result.users || []);
    } catch (error) {
      notify(error instanceof Error ? error.message : "用户列表加载失败", "error");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  async function submit() {
    if (!username || password.length < 8) {
      notify("请输入用户名和至少 8 位密码", "warning");
      return;
    }
    try {
      await createUser(username, password, tier);
      notify("用户已创建", "success");
      setUsername("");
      setPassword("");
      await refresh();
    } catch (error) {
      notify(error instanceof Error ? error.message : "创建用户失败", "error");
    }
  }

  async function changeTier(usernameValue: string, nextTier: string) {
    try {
      await setUserTier(usernameValue, nextTier);
      notify("等级已更新", "success");
      await refresh();
    } catch (error) {
      notify(error instanceof Error ? error.message : "更新等级失败", "error");
    }
  }

  async function remove(usernameValue: string) {
    try {
      await deleteUser(usernameValue);
      notify("用户已删除", "success");
      await refresh();
    } catch (error) {
      notify(error instanceof Error ? error.message : "删除失败", "error");
    }
  }

  return (
    <Box className="admin-grid">
      <SectionCard title="创建用户">
        <Stack spacing={2}>
          <TextField label="用户名" value={username} onChange={(event) => setUsername(event.target.value)} />
          <TextField label="密码" type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
          <Select value={tier} onChange={(event) => setTier(event.target.value)}>
            <MenuItem value="free">免费版</MenuItem>
            <MenuItem value="pro">专业版</MenuItem>
          </Select>
          <Button variant="contained" onClick={() => void submit()}>创建</Button>
        </Stack>
      </SectionCard>
      <SectionCard title="用户" action={<Button startIcon={<RefreshOutlined />} onClick={() => void refresh()} disabled={loading}>刷新</Button>}>
        <Paper variant="outlined" className="table-shell">
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>用户</TableCell>
                <TableCell>等级</TableCell>
                <TableCell>创建时间</TableCell>
                <TableCell align="right">操作</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {users.map((user) => (
                <TableRow key={user.username}>
                  <TableCell><Typography sx={{ fontWeight: 700 }}>{user.username}</Typography></TableCell>
                  <TableCell>
                    <Select size="small" value={user.tier} disabled={user.username === "admin"} onChange={(event) => void changeTier(user.username, event.target.value)}>
                      <MenuItem value="free">免费版</MenuItem>
                      <MenuItem value="pro">专业版</MenuItem>
                    </Select>
                  </TableCell>
                  <TableCell>{formatDate(user.created_at)}</TableCell>
                  <TableCell align="right">
                    {user.username === "admin" ? <Chip size="small" label="内置" /> : <IconButton color="error" onClick={() => void remove(user.username)}><DeleteOutlined /></IconButton>}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Paper>
      </SectionCard>
    </Box>
  );
}

function statusChip(ok: boolean, yes = "正常", no = "异常") {
  return <Chip size="small" color={ok ? "success" : "error"} label={ok ? yes : no} />;
}

function formatBytes(value?: number | null) {
  if (value == null) return "-";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function pathLabel(key: string) {
  return ({
    repo_root: "项目根目录",
    web_root: "Web 目录",
    job_root: "任务缓存",
    upload_root: "上传缓存",
    output: "输出目录",
    react_dist: "React 产物",
    packer: "加固脚本",
    release_manifest: "发布清单",
    sdk_root: "Android SDK",
    build_tools: "Build Tools",
    ndk: "Android NDK",
    apktool: "apktool",
    zipalign: "zipalign",
    apksigner: "apksigner",
  } as Record<string, string>)[key] || key;
}

function PathTable({ rows, showConfigured = false }: { rows: Array<[string, PathDiagnostic]>; showConfigured?: boolean }) {
  return (
    <Paper variant="outlined" className="table-shell ops-table">
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell width={150}>项目</TableCell>
            {showConfigured ? <TableCell width={92}>配置</TableCell> : null}
            <TableCell width={92}>状态</TableCell>
            <TableCell width={92}>可写</TableCell>
            <TableCell width={110}>大小</TableCell>
            <TableCell>路径</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rows.map(([key, item]) => (
            <TableRow key={`${key}-${item.path || "empty"}`}>
              <TableCell><Typography sx={{ fontWeight: 700 }}>{pathLabel(key)}</Typography></TableCell>
              {showConfigured ? <TableCell>{statusChip(Boolean(item.configured), "已配置", "未配置")}</TableCell> : null}
              <TableCell>{statusChip(Boolean(item.usable ?? item.exists), "可用", "缺失")}</TableCell>
              <TableCell>{typeof item.writable === "boolean" ? statusChip(item.writable, "可写", "只读") : <Chip size="small" label="-" />}</TableCell>
              <TableCell>{formatBytes(item.size)}</TableCell>
              <TableCell><Typography className="ops-path">{item.path || "-"}</Typography></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Paper>
  );
}

function OpsPage({ notify }: { notify: (message: string, severity?: AlertColor) => void }) {
  const [diagnostics, setDiagnostics] = useState<DiagnosticsPayload | null>(null);
  const [loading, setLoading] = useState(false);

  async function refresh() {
    setLoading(true);
    try {
      setDiagnostics(await getDiagnostics());
    } catch (error) {
      notify(error instanceof Error ? error.message : "诊断信息加载失败", "error");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  const pathRows = Object.entries(diagnostics?.paths || {});
  const toolRows = Object.entries(diagnostics?.toolchain || {});
  const commandRows = Object.entries(diagnostics?.commands || {});
  const envRows = Object.entries(diagnostics?.environment || {});
  const shellCandidates = (diagnostics?.shell.candidates || []).map((item, index) => [`shell_${index + 1}`, item] as [string, PathDiagnostic]);
  const missingTools = toolRows.filter(([, item]) => item.configured && !item.usable).length;
  const missingRequired = [
    diagnostics?.paths.packer?.exists,
    diagnostics?.paths.react_dist?.exists,
    diagnostics?.shell.available,
    diagnostics?.database.connected,
  ].filter((value) => value === false).length + missingTools;

  return (
    <Stack spacing={2.5}>
      <Alert
        severity="warning"
        variant="outlined"
        action={<Button startIcon={<RefreshOutlined />} onClick={() => void refresh()} disabled={loading}>刷新</Button>}
      >
        此页面仅管理员可见，包含服务器绝对路径、工具链状态和部署开关；不要开放给普通用户或截图外发。
      </Alert>

      <Box className="metrics-grid">
        <MetricCard label="综合状态" value={missingRequired ? `${missingRequired} 项异常` : "健康"} icon={<ScienceOutlined />} tone={missingRequired ? "warning" : "success"} />
        <MetricCard label="Shell APK" value={diagnostics?.shell.available ? "可用" : "缺失"} icon={<ShieldOutlined />} tone={diagnostics?.shell.available ? "success" : "warning"} />
        <MetricCard label="数据库" value={diagnostics?.database.connected ? "已连接" : "未连接"} icon={<StorageOutlined />} tone={diagnostics?.database.connected ? "success" : "warning"} />
        <MetricCard label="公开脱敏" value={diagnostics?.flags.public_api_redaction ? "已开启" : "未开启"} icon={<SecurityOutlined />} tone={diagnostics?.flags.public_api_redaction ? "success" : "warning"} />
      </Box>

      <Box className="ops-grid">
        <SectionCard title="运行环境">
          <Stack spacing={1.25}>
            <Stack direction="row" sx={{ justifyContent: "space-between", gap: 2 }}>
              <Typography color="text.secondary">Python</Typography>
              <Typography className="mono-line">{String(diagnostics?.server.python || "-")}</Typography>
            </Stack>
            <Stack direction="row" sx={{ justifyContent: "space-between", gap: 2 }}>
              <Typography color="text.secondary">平台</Typography>
              <Typography className="mono-line">{String(diagnostics?.server.platform || "-")}</Typography>
            </Stack>
            <Stack direction="row" sx={{ justifyContent: "space-between", gap: 2 }}>
              <Typography color="text.secondary">工作目录</Typography>
              <Typography className="ops-path">{String(diagnostics?.server.cwd || "-")}</Typography>
            </Stack>
            <Stack direction="row" sx={{ justifyContent: "space-between", gap: 2 }}>
              <Typography color="text.secondary">数据库延迟</Typography>
              <Typography>{diagnostics?.database.latency_ms == null ? "-" : `${diagnostics.database.latency_ms} ms`}</Typography>
            </Stack>
            <Typography variant="caption" color="text.secondary">更新时间：{diagnostics ? formatDate(diagnostics.timestamp) : "-"}</Typography>
          </Stack>
        </SectionCard>

        <SectionCard title="商业上线开关">
          <Stack direction="row" sx={{ gap: 1, flexWrap: "wrap" }}>
            <Chip color={diagnostics?.flags.production ? "success" : "warning"} label={`生产模式 ${diagnostics?.flags.production ? "开启" : "关闭"}`} />
            <Chip color={diagnostics?.flags.public_api_redaction ? "success" : "error"} label={`公开脱敏 ${diagnostics?.flags.public_api_redaction ? "开启" : "关闭"}`} />
            <Chip color={diagnostics?.flags.public_docs_enabled ? "warning" : "success"} label={`公开文档 ${diagnostics?.flags.public_docs_enabled ? "开启" : "关闭"}`} />
            <Chip color={diagnostics?.flags.monitor_token_configured ? "success" : "warning"} label={`监控令牌 ${diagnostics?.flags.monitor_token_configured ? "已配置" : "未配置"}`} />
          </Stack>
          <Divider sx={{ my: 2 }} />
          <Typography variant="caption" color="text.secondary">CORS</Typography>
          <Typography className="ops-path">{diagnostics?.flags.cors_origins?.join(", ") || "-"}</Typography>
        </SectionCard>
      </Box>

      <SectionCard title="服务器路径">
        <PathTable rows={pathRows} />
      </SectionCard>

      <SectionCard title="Shell APK 候选">
        <Stack spacing={1.5}>
          {diagnostics?.shell.default?.path ? (
            <Alert severity={diagnostics.shell.available ? "success" : "error"} variant="outlined">
              当前默认 Shell：<span className="ops-inline-path">{diagnostics.shell.default.path}</span>
            </Alert>
          ) : null}
          <PathTable rows={shellCandidates} />
        </Stack>
      </SectionCard>

      <SectionCard title="Android 工具链">
        <PathTable rows={toolRows} showConfigured />
      </SectionCard>

      <Box className="ops-grid">
        <SectionCard title="命令版本">
          <Paper variant="outlined" className="table-shell ops-table">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell width={120}>命令</TableCell>
                  <TableCell width={90}>状态</TableCell>
                  <TableCell>版本输出</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {commandRows.map(([key, item]) => (
                  <TableRow key={key}>
                    <TableCell><Typography sx={{ fontWeight: 700 }}>{key}</Typography></TableCell>
                    <TableCell>{statusChip(item.ok, "可执行", "失败")}</TableCell>
                    <TableCell><Typography className="ops-path">{item.version || item.error || item.command}</Typography></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>
        </SectionCard>

        <SectionCard title="环境变量">
          <Paper variant="outlined" className="table-shell ops-table">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>变量</TableCell>
                  <TableCell width={100}>状态</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {envRows.map(([key, value]) => (
                  <TableRow key={key}>
                    <TableCell><Typography className="ops-path">{key}</Typography></TableCell>
                    <TableCell>{statusChip(Boolean(value), "已设置", "未设置")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>
        </SectionCard>
      </Box>
    </Stack>
  );
}

function PasswordDialog({ open, onClose, notify }: { open: boolean; onClose: () => void; notify: (message: string, severity?: AlertColor) => void }) {
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit() {
    if (newPassword !== confirm) {
      notify("两次密码不一致", "warning");
      return;
    }
    if (newPassword.length < 8) {
      notify("新密码至少 8 位", "warning");
      return;
    }
    setLoading(true);
    try {
      await changePassword(oldPassword, newPassword);
      notify("密码已修改", "success");
      setOldPassword("");
      setNewPassword("");
      setConfirm("");
      onClose();
    } catch (error) {
      notify(error instanceof Error ? error.message : "密码修改失败", "error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle>修改密码</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ pt: 1 }}>
          <TextField label="当前密码" type="password" value={oldPassword} onChange={(event) => setOldPassword(event.target.value)} />
          <TextField label="新密码" type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
          <TextField label="确认新密码" type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} />
          <Button variant="contained" onClick={() => void submit()} disabled={loading}>确认修改</Button>
        </Stack>
      </DialogContent>
    </Dialog>
  );
}

export default function App() {
  const [auth, setAuth] = useState<AuthState>(() => loadAuth());
  const [booting, setBooting] = useState(true);
  const [collapsed, setCollapsed] = useState(false);
  const [dark, setDark] = useState(() => localStorage.getItem("enko_react_theme") === "dark");
  const [activePage, setActivePage] = useState<PageKey>(() => pageFromPath(window.location.pathname));
  const [stats, setStats] = useState<StatsPayload | null>(null);
  const [health, setHealth] = useState<HealthPayload | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [selectedJob, setSelectedJob] = useState<Job | null>(null);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [jobPreset, setJobPreset] = useState<PresetApplication | null>(null);
  const [toast, setToast] = useState<ToastState>({ open: false, message: "", severity: "info" });

  const notify = (messageText: string, severity: AlertColor = "info") => {
    setToast({ open: true, message: messageText, severity });
  };

  const navigatePage = useCallback((page: PageKey, replace = false) => {
    const nextPage = pageForAuth(page, auth.isAdmin);
    setActivePage(nextPage);
    const nextPath = pagePaths[nextPage];
    if (window.location.pathname !== nextPath) {
      if (replace) window.history.replaceState(null, "", nextPath);
      else window.history.pushState(null, "", nextPath);
    }
  }, [auth.isAdmin]);

  const syncRouteForAuth = useCallback((isAdmin: boolean) => {
    const nextPage = pageForAuth(pageFromPath(window.location.pathname), isAdmin);
    setActivePage(nextPage);
    const nextPath = pagePaths[nextPage];
    if (window.location.pathname !== nextPath) {
      window.history.replaceState(null, "", nextPath);
    }
  }, []);

  const visibleNavItems = useMemo(
    () => (Object.entries(navItems) as Array<[PageKey, { label: string; icon: ReactNode }]>)
      .filter(([key]) => !adminOnlyPages.has(key) || auth.isAdmin),
    [auth.isAdmin],
  );

  const muiTheme = useMemo(() => createTheme({
    palette: {
      mode: dark ? "dark" : "light",
      primary: { main: "#2563eb" },
      secondary: { main: "#7c3aed" },
      success: { main: "#16a34a" },
      warning: { main: "#d97706" },
      error: { main: "#dc2626" },
      background: dark ? { default: "#0b1020", paper: "#111827" } : { default: "#f7f8fb", paper: "#ffffff" },
    },
    shape: { borderRadius: 8 },
    typography: {
      fontFamily: "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
      h4: { letterSpacing: 0 },
      h5: { letterSpacing: 0 },
      h6: { letterSpacing: 0 },
      button: { textTransform: "none", fontWeight: 700 },
    },
    components: {
      MuiPaper: { styleOverrides: { root: { backgroundImage: "none" } } },
      MuiButton: { styleOverrides: { root: { borderRadius: 8 } } },
    },
  }), [dark]);

  async function refreshData() {
    try {
      const [nextStats, nextHealth, nextJobs] = await Promise.all([getStats(), getHealth(), listJobs()]);
      setStats(nextStats);
      setHealth(nextHealth);
      setJobs(nextJobs.jobs || []);
    } catch (error) {
      notify(error instanceof Error ? error.message : "数据加载失败", "error");
    }
  }

  async function removeJob(job: Job) {
    if (!window.confirm(`确认删除任务 ${job.id}？`)) return;
    try {
      await deleteJob(job.id);
      notify("任务已删除", "success");
      if (selectedJob?.id === job.id) setSelectedJob(null);
      await refreshData();
    } catch (error) {
      notify(error instanceof Error ? error.message : "删除失败", "error");
    }
  }

  useEffect(() => {
    async function boot() {
      if (!auth.token) {
        setBooting(false);
        return;
      }
      try {
        const checked = await checkAuth();
        saveAuth(auth.token, checked.username, checked.tier, checked.tier_limits, checked.is_admin);
        setAuth(loadAuth());
        syncRouteForAuth(checked.is_admin);
        await refreshData();
      } catch {
        clearAuth();
        setAuth(loadAuth());
      } finally {
        setBooting(false);
      }
    }
    void boot();
  }, []);

  useEffect(() => {
    localStorage.setItem("enko_react_theme", dark ? "dark" : "light");
  }, [dark]);

  useEffect(() => {
    const onPopState = () => {
      setActivePage(pageForAuth(pageFromPath(window.location.pathname), loadAuth().isAdmin));
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    if (auth.token && adminOnlyPages.has(activePage) && !auth.isAdmin) {
      navigatePage("dashboard", true);
    }
  }, [activePage, auth.isAdmin, auth.token, navigatePage]);

  if (booting) {
    return <Box className="boot-screen"><CircularProgress size={22} /> 正在进入 Enko Forge...</Box>;
  }

  if (!auth.token) {
    return (
      <ThemeProvider theme={muiTheme}>
        <CssBaseline />
        <LoginPage onLogin={(nextAuth) => { setAuth(nextAuth); syncRouteForAuth(nextAuth.isAdmin); void refreshData(); }} notify={notify} />
        <Snackbar open={toast.open} autoHideDuration={3600} onClose={() => setToast((current) => ({ ...current, open: false }))}>
          <Alert severity={toast.severity} variant="filled">{toast.message}</Alert>
        </Snackbar>
      </ThemeProvider>
    );
  }

  const selectedMeta = navItems[activePage];
  const page = activePage === "dashboard"
    ? <DashboardPage stats={stats} health={health} jobs={jobs} onRefresh={refreshData} onOpenJob={setSelectedJob} />
    : activePage === "new-job"
      ? <NewJobPage health={health} preset={jobPreset} notify={notify} onCreated={(job) => { setJobs((current) => [job, ...current]); setSelectedJob(job); navigatePage("jobs"); void refreshData(); }} />
      : activePage === "jobs"
        ? <JobsPage jobs={jobs} onRefresh={refreshData} onOpenJob={setSelectedJob} onDeleteJob={(job) => void removeJob(job)} />
        : activePage === "reports"
          ? <ReportsPage jobs={jobs} onOpenJob={setSelectedJob} notify={notify} />
          : activePage === "profiles"
            ? <ProfilesPage onApply={(patch) => { setJobPreset({ id: Date.now(), patch }); navigatePage("new-job"); }} />
            : activePage === "admin"
              ? <AdminPage notify={notify} />
              : <OpsPage notify={notify} />;

  const currentDrawerWidth = collapsed ? collapsedWidth : drawerWidth;

  return (
    <ThemeProvider theme={muiTheme}>
      <CssBaseline />
      <Box className="app-shell">
        <Drawer
          variant="permanent"
          className="app-drawer"
          sx={{ "& .MuiDrawer-paper": { width: currentDrawerWidth, transition: "width .18s ease", overflowX: "hidden", borderRight: 1, borderColor: "divider" } }}
        >
          <Stack className="brand" direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
            <Box className="brand-mark"><SecurityOutlined /></Box>
            {!collapsed ? (
              <Box>
                <Typography sx={{ fontWeight: 800 }}>Enko Forge</Typography>
                <Typography variant="caption" color="text.secondary">加固控制台</Typography>
              </Box>
            ) : null}
          </Stack>
          <List sx={{ px: 1 }}>
            {visibleNavItems.map(([key, item]) => (
              <ListItemButton
                key={key}
                selected={activePage === key}
                onClick={() => navigatePage(key)}
                sx={{ borderRadius: 2, minHeight: 44, mb: 0.5, justifyContent: collapsed ? "center" : "flex-start" }}
              >
                <ListItemIcon sx={{ minWidth: collapsed ? 0 : 40, color: "inherit" }}>{item.icon}</ListItemIcon>
                {!collapsed ? <ListItemText primary={item.label} /> : null}
              </ListItemButton>
            ))}
          </List>
          <Box sx={{ flex: 1 }} />
          {!collapsed ? <Typography variant="caption" color="text.secondary" sx={{ p: 2 }}>本地控制台 v5</Typography> : null}
        </Drawer>
        <Box className="mobile-nav" component="nav" sx={{ gridTemplateColumns: `repeat(${visibleNavItems.length}, minmax(0, 1fr))` }}>
          {visibleNavItems.map(([key, item]) => (
            <button
              key={key}
              type="button"
              className={activePage === key ? "mobile-nav-item active" : "mobile-nav-item"}
              onClick={() => navigatePage(key)}
            >
              <span>{item.icon}</span>
              <small>{item.label}</small>
            </button>
          ))}
        </Box>
        <Box className="app-main" sx={{ ml: `${currentDrawerWidth}px` }}>
          <AppBar position="sticky" color="transparent" elevation={0} className="app-header">
            <Toolbar>
              <IconButton onClick={() => setCollapsed((value) => !value)} edge="start">
                {collapsed ? <MenuOutlined /> : <MenuOpenOutlined />}
              </IconButton>
              <Stack direction="row" spacing={1.25} sx={{ minWidth: 0, alignItems: "center" }}>
                {selectedMeta.icon}
                <Typography sx={{ fontWeight: 800 }}>{selectedMeta.label}</Typography>
              </Stack>
              <Box sx={{ flex: 1 }} />
              <TextField
                className="global-search"
                size="small"
                placeholder="搜索任务、报告、产物"
              />
              <Chip className="engine-chip" size="small" color={health?.ok ? "success" : "warning"} label={health?.ok ? "引擎在线" : "离线"} />
              <Tooltip title="切换主题"><IconButton onClick={() => setDark((value) => !value)}><AutoAwesomeOutlined /></IconButton></Tooltip>
              <Tooltip title="修改密码"><IconButton onClick={() => setPasswordOpen(true)}><KeyOutlined /></IconButton></Tooltip>
              <Avatar sx={{ width: 32, height: 32 }}>{(auth.username || "A").slice(0, 1).toUpperCase()}</Avatar>
              <Typography className="username-label" variant="body2">{auth.username || "admin"}</Typography>
              <Tooltip title="退出登录"><IconButton onClick={() => { clearAuth(); setAuth(loadAuth()); }}><LogoutOutlined /></IconButton></Tooltip>
            </Toolbar>
          </AppBar>
          <Box className="app-content">
            <PageMasthead page={activePage} onNewJob={() => navigatePage("new-job")} />
            {page}
          </Box>
        </Box>
        <JobDetailDrawer job={selectedJob} open={Boolean(selectedJob)} onClose={() => setSelectedJob(null)} onChanged={refreshData} notify={notify} />
        <PasswordDialog open={passwordOpen} onClose={() => setPasswordOpen(false)} notify={notify} />
        <Snackbar open={toast.open} autoHideDuration={3600} onClose={() => setToast((current) => ({ ...current, open: false }))}>
          <Alert severity={toast.severity} variant="filled">{toast.message}</Alert>
        </Snackbar>
      </Box>
    </ThemeProvider>
  );
}
