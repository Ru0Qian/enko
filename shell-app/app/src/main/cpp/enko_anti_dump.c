#include "enko_anti_dump.h"
#include "enko_key.h"   /* enko_secure_wipe */
#include "enko_obfstr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <android/log.h>
/* "EnkoAntiDump" (len=12) */
OBFSTR_DECL(obs_tag_antidump, 0x82,0xA9,0xAC,0xA8,0x86,0xA9,0xB3,0xAE,0x83,0xB2,0xAA,0xB7);
static char g_dump_tag[13];
static void ensure_dump_tag(void) {
    if (g_dump_tag[0] == '\0') obs_tag_antidump_dec(g_dump_tag, 12);
}
#define LOGW(...) do { ensure_dump_tag(); __android_log_print(ANDROID_LOG_WARN, g_dump_tag, __VA_ARGS__); } while(0)

/* ================================================================
 * 1. PR_SET_DUMPABLE 鈥?the single most effective anti-dump measure.
 *
 *    Effect:
 *    - /proc/self/mem becomes unreadable by non-root processes.
 *    - Core dumps are disabled.
 *    - process_vm_readv from other UIDs is blocked.
 *    - ptrace attach from non-root is blocked (supplements our
 *      existing PTRACE_TRACEME).
 *
 *    Limitation: root can still override.  We address that with
 *    the other layers below.
 * ================================================================ */

enum {
    DUMP_FLAG_TOOL = 1,          /* known dump tool process */
    DUMP_FLAG_MEM_EDITOR = 2,    /* GameGuardian / memory editor */
    DUMP_FLAG_PROC_FD = 4,       /* another process opened our maps/mem */
    DUMP_FLAG_SELF_FD_LEAK = 8,  /* suspicious self maps/mem fd */
    DUMP_FLAG_COREDUMP_WEAK = 16,/* coredump_filter not hardened */
    DUMP_FLAG_WEAK_HEURISTIC = 32,/* weak process-name match only */
};

static void harden_coredump_filter(void) {
    static const char *path = "/proc/self/coredump_filter";
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return;
    }
    /* Disable dumping of all mapping classes. */
    (void)write(fd, "0\n", 2);
    close(fd);
}

static int check_coredump_filter_weak(void) {
    static const char *path = "/proc/self/coredump_filter";
    FILE *f = fopen(path, "r");
    if (!f) {
        /* If unavailable, avoid false positives. */
        return 0;
    }
    char buf[64] = {0};
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    /* Linux exposes this as a hex bitmask string. */
    char *end = NULL;
    unsigned long mask = strtoul(buf, &end, 16);
    (void)end;
    return (mask != 0UL) ? 1 : 0;
}

static void disable_dumpable(void) {
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    /* Some ROMs re-enable dumpable after execve or certain signals.
     * Set it again defensively. */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    harden_coredump_filter();
}

/* ================================================================
 * 2. Fork-bomb detection via SIGCHLD.
 *
 *    Attack:  attacker injects code that fork()s the process, then
 *    reads /proc/<child>/mem from the parent (child inherits memory).
 *
 *    Defense: we install a SIGCHLD handler that _exit()s immediately.
 *    Normal Android apps never fork(), so any SIGCHLD means trouble.
 * ================================================================ */

static void sigchld_handler(int sig) {
    (void)sig;
    /* Signal context: keep async-signal-safe and fail closed. */
    _exit(1);
}

static void install_fork_detection(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_NOCLDSTOP;  /* Only on child termination, not stop. */
    sigaction(SIGCHLD, &sa, NULL);
}

/* ================================================================
 * 3. Background thread: scan /proc for dump tool processes.
 * ================================================================ */

/* Known dump-tool process names (obfuscated). */
OBFSTR_DECL(obs_dexdump, 0xA3,0xA2,0xBF,0xA3,0xB2,0xAA,0xB7);
OBFSTR_DECL(obs_dump_dex, 0xA3,0xB2,0xAA,0xB7,0x98,0xA3,0xA2,0xBF);
OBFSTR_DECL(obs_dex2oat, 0xA3,0xA2,0xBF,0xF5,0xA8,0xA6,0xB3);
OBFSTR_DECL(obs_gameguardian, 0xA0,0xA6,0xAA,0xA2,0xA0,0xB2,0xA6,0xB5,0xA3,0xAE,0xA6,0xA9);
OBFSTR_DECL(obs_gg_, 0xA0,0xA0,0x98);
OBFSTR_DECL(obs_memoryeditor, 0xAA,0xA2,0xAA,0xA8,0xB5,0xBE,0xA2,0xA3,0xAE,0xB3,0xA8,0xB5);
OBFSTR_DECL(obs_memdump, 0xAA,0xA2,0xAA,0xA3,0xB2,0xAA,0xB7);
OBFSTR_DECL(obs_fridump, 0xA1,0xB5,0xAE,0xA3,0xB2,0xAA,0xB7);
OBFSTR_DECL(obs_objection, 0xA8,0xA5,0xAD,0xA2,0xA4,0xB3,0xAE,0xA8,0xA9);
OBFSTR_DECL(obs_r2frida, 0xB5,0xF5,0xA1,0xB5,0xAE,0xA3,0xA6);
OBFSTR_DECL(obs_xmem, 0xBF,0xAA,0xA2,0xAA);

#define NUM_DUMP_TOOLS 11
static void decrypt_dump_tool_names(char bufs[NUM_DUMP_TOOLS][16]) {
    obs_dexdump_dec(bufs[0], 7);
    obs_dump_dex_dec(bufs[1], 8);
    obs_dex2oat_dec(bufs[2], 7);
    obs_gameguardian_dec(bufs[3], 12);
    obs_gg__dec(bufs[4], 3);
    obs_memoryeditor_dec(bufs[5], 12);
    obs_memdump_dec(bufs[6], 7);
    obs_fridump_dec(bufs[7], 7);
    obs_objection_dec(bufs[8], 9);
    obs_r2frida_dec(bufs[9], 7);
    obs_xmem_dec(bufs[10], 4);
}

static int read_cmdline(int pid, char *out, size_t out_sz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(out, 1, out_sz - 1, f);
    fclose(f);
    out[n] = '\0';
    /* cmdline uses \0 between args; replace with spaces for strstr. */
    for (size_t i = 0; i < n; i++) {
        if (out[i] == '\0') out[i] = ' ';
    }
    return 0;
}

static int check_self_proc_fd_leaks(void) {
    int my_pid = getpid();
    char self_maps[64], self_mem[64];
    char pid_maps[64], pid_mem[64];
    snprintf(self_maps, sizeof(self_maps), "/proc/self/maps");
    snprintf(self_mem, sizeof(self_mem), "/proc/self/mem");
    snprintf(pid_maps, sizeof(pid_maps), "/proc/%d/maps", my_pid);
    snprintf(pid_mem, sizeof(pid_mem), "/proc/%d/mem", my_pid);

    for (int fd = 3; fd < 512; fd++) {
        char fd_path[64];
        char link[256];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        ssize_t len = readlink(fd_path, link, sizeof(link) - 1);
        if (len <= 0) continue;
        link[len] = '\0';
        if (strcmp(link, self_maps) == 0 || strcmp(link, self_mem) == 0 ||
            strcmp(link, pid_maps) == 0 || strcmp(link, pid_mem) == 0) {
            return 1;
        }
    }
    return 0;
}

static int scan_proc_for_dump_tools(int deep_scan) {
    int flags = 0;
    DIR *proc = opendir("/proc");
    if (!proc) return 0;

    /* Decrypt tool names onto stack. */
    char tool_names[NUM_DUMP_TOOLS][16];
    decrypt_dump_tool_names(tool_names);

    struct dirent *ent;
    char cmdline[256];
    int my_pid = getpid();

    while ((ent = readdir(proc)) != NULL) {
        int pid = atoi(ent->d_name);
        if (pid <= 0 || pid == my_pid) continue;

        if (read_cmdline(pid, cmdline, sizeof(cmdline)) != 0) continue;

        for (char *p = cmdline; *p; p++) {
            if (*p >= 'A' && *p <= 'Z') *p += 32;
        }

        for (int i = 0; i < NUM_DUMP_TOOLS; i++) {
            if (strstr(cmdline, tool_names[i])) {
                /* indices 3,4,5 are gameguardian, gg_, memoryeditor */
                if (i == 3 || i == 4 || i == 5) {
                    flags |= DUMP_FLAG_MEM_EDITOR;
                } else if (i == 2) {
                    /* dex2oat is common on many ROMs: keep as weak signal only. */
                    flags |= DUMP_FLAG_WEAK_HEURISTIC;
                } else {
                    flags |= DUMP_FLAG_TOOL;
                }
                break;
            }
        }
    }
    closedir(proc);

    if (check_self_proc_fd_leaks()) {
        flags |= DUMP_FLAG_SELF_FD_LEAK;
    }
    if (check_coredump_filter_weak()) {
        flags |= DUMP_FLAG_COREDUMP_WEAK;
    }
    if (!deep_scan) {
        return flags;
    }

    /* Additionally check if anyone else has our /proc/self/maps open.
     * Read /proc/self/fdinfo is not practical, but we can check whether
     * /proc/<other>/fd/<n> points to /proc/<mypid>/maps or /proc/<mypid>/mem. */
    proc = opendir("/proc");
    if (!proc) return flags;

    char my_maps[64], my_mem[64];
    snprintf(my_maps, sizeof(my_maps), "/proc/%d/maps", my_pid);
    snprintf(my_mem, sizeof(my_mem), "/proc/%d/mem", my_pid);

    while ((ent = readdir(proc)) != NULL) {
        int pid = atoi(ent->d_name);
        if (pid <= 0 || pid == my_pid) continue;

        char fd_dir[64];
        snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
        DIR *fds = opendir(fd_dir);
        if (!fds) continue;

        struct dirent *fd_ent;
        while ((fd_ent = readdir(fds)) != NULL) {
            char fd_path[128], link[256];
            snprintf(fd_path, sizeof(fd_path), "%s/%s", fd_dir, fd_ent->d_name);
            ssize_t len = readlink(fd_path, link, sizeof(link) - 1);
            if (len <= 0) continue;
            link[len] = '\0';
            if (strcmp(link, my_maps) == 0 || strcmp(link, my_mem) == 0) {
                flags |= DUMP_FLAG_PROC_FD;  /* Someone has our maps/mem open. */
                break;
            }
        }
        closedir(fds);
        if (flags & DUMP_FLAG_PROC_FD) break;
    }
    closedir(proc);

    return flags;
}

/* Background thread: periodically re-enforce dumpable=0 and scan. */
static volatile int g_dump_watchdog_running = 0;

static void *dump_watchdog_thread(void *arg) {
    (void)arg;
    unsigned int tick = 0;
    unsigned int self_fd_streak = 0;
    unsigned int proc_fd_streak = 0;
    while (g_dump_watchdog_running) {
        /* Re-enforce non-dumpable (some ROMs reset it). */
        disable_dumpable();

        int deep_scan = ((tick++ % 3U) == 0U) ? 1 : 0;
        int flags = scan_proc_for_dump_tools(deep_scan);

        if (flags & DUMP_FLAG_SELF_FD_LEAK) {
            self_fd_streak++;
        } else {
            self_fd_streak = 0;
        }
        if (flags & DUMP_FLAG_PROC_FD) {
            proc_fd_streak++;
        } else {
            proc_fd_streak = 0;
        }

        /*
         * Fail closed on strong cross-process signals immediately.
         * For self-fd leak, require consecutive hits to reduce false positives
         * caused by short-lived self-inspection probes.
         */
        if (flags & (DUMP_FLAG_TOOL | DUMP_FLAG_MEM_EDITOR)) {
            LOGW("dump tool detected (flags=%d)", flags);
            _exit(1);
        }
        if (proc_fd_streak >= 3U) {
            /*
             * Cross-process /proc/<pid>/fd -> /proc/self/{maps,mem} can be
             * generated by OEM/system telemetry and monitoring daemons.
             * Keep as weak signal to reduce production false kills.
             */
            LOGW("persistent proc-fd probe detected (flags=%d, streak=%u, weak signal, continue)",
                 flags, proc_fd_streak);
            proc_fd_streak = 0;
        }
        if (self_fd_streak >= 3U) {
            /*
             * Self-fd leak is noisy on some environments (adb/input tooling,
             * OEM telemetry). Keep it as weak signal to avoid false kills.
             */
            LOGW("persistent self-fd leak detected (flags=%d, streak=%u, weak signal, continue)",
                 flags, self_fd_streak);
            self_fd_streak = 0;
        }

        /*
         * If coredump_filter was re-enabled by external tampering, enforce it
         * once more. If it still stays non-zero, keep it as a weak signal only.
         * Some kernels/ROMs do not allow writing all-zero here.
         */
        if (flags & DUMP_FLAG_COREDUMP_WEAK) {
            harden_coredump_filter();
            if (check_coredump_filter_weak()) {
                LOGW("coredump_filter hardening failed (weak signal, continue)");
            }
        }

        sleep(deep_scan ? 3 : 2);
    }
    return NULL;
}

/* ================================================================
 * Public API
 * ================================================================ */

void enko_anti_dump_init(void) {
    disable_dumpable();
    install_fork_detection();

    g_dump_watchdog_running = 1;
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, dump_watchdog_thread, NULL);
    pthread_attr_destroy(&attr);
}

int enko_mark_no_dump(void *addr, size_t len) {
    if (!addr || len == 0) return -1;

    /* Page-align the address downward. */
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~(page_size - 1);
    uintptr_t end = ((uintptr_t)addr + len + page_size - 1) & ~(page_size - 1);
    size_t aligned_len = end - start;

#ifdef MADV_DONTDUMP
    return madvise((void *)start, aligned_len, MADV_DONTDUMP);
#else
    /* MADV_DONTDUMP = 16 on Linux; define manually for older NDK headers. */
    return madvise((void *)start, aligned_len, 16);
#endif
}

int enko_protect_dex_region(void *addr, size_t len) {
    if (!addr || len == 0) return -1;

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~(page_size - 1);
    uintptr_t end = ((uintptr_t)addr + len + page_size - 1) & ~(page_size - 1);
    size_t aligned_len = end - start;

    /* PROT_NONE: no read/write/exec — blocks /proc/self/mem reads. */
    int rc = mprotect((void *)start, aligned_len, PROT_NONE);
    if (rc != 0) {
        LOGW("mprotect PROT_NONE failed on %p+%zu: %s",
             addr, len, strerror(errno));
    }
    return rc;
}

int enko_wipe_memory(void *addr, size_t len) {
    if (!addr || len == 0) return -1;

    /* Volatile write to prevent compiler optimisation. */
    volatile uint8_t *p = (volatile uint8_t *)addr;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }

    /* Hint kernel to release the physical pages.
     * The virtual mapping stays valid (reads return zero). */
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~(page_size - 1);
    uintptr_t end = ((uintptr_t)addr + len + page_size - 1) & ~(page_size - 1);
    size_t aligned_len = end - start;

    /* MADV_DONTNEED on anonymous/private pages zeros them. */
    madvise((void *)start, aligned_len, MADV_DONTNEED);
    return 0;
}

int enko_detect_dump_tools(void) {
    return scan_proc_for_dump_tools(1);
}

