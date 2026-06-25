#include "enko_anti_debug.h"
#include "enko_obfstr.h"
#include "enko_key.h"    /* enko_derive_payload_key 鈥?checked by anti-hook */
#include "enko_gcm.h"    /* enko_gcm_decrypt 鈥?checked by anti-hook */

#include "enko_anti_dump.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <link.h>
#include <elf.h>
#include <sys/utsname.h>

#include <android/log.h>

/* ---- Obfuscated TAG ---- */
/* "EnkoNative" (len=10) */
OBFSTR_DECL(obs_tag_native, 0x82,0xA9,0xAC,0xA8,0x89,0xA6,0xB3,0xAE,0xB1,0xA2);
#define OBS_TAG_LEN 10
static char g_tag[OBS_TAG_LEN + 1];
static void ensure_tag(void) {
    if (g_tag[0] == '\0') obs_tag_native_dec(g_tag, OBS_TAG_LEN);
}
#define LOGW(...) do { ensure_tag(); __android_log_print(ANDROID_LOG_WARN, g_tag, __VA_ARGS__); } while(0)

/* ---- Obfuscated strings ---- */

/* /proc/self/status (len=17) */
OBFSTR_DECL(obs_proc_self_status, 0xE8,0xB7,0xB5,0xA8,0xA4,0xE8,0xB4,0xA2,0xAB,0xA1,0xE8,0xB4,0xB3,0xA6,0xB3,0xB2,0xB4);
/* /proc/self/wchan (len=16) */
OBFSTR_DECL(obs_proc_self_wchan, 0xE8,0xB7,0xB5,0xA8,0xA4,0xE8,0xB4,0xA2,0xAB,0xA1,0xE8,0xB0,0xA4,0xAF,0xA6,0xA9);
/* /proc/self/task (len=15) */
OBFSTR_DECL(obs_proc_self_task, 0xE8,0xB7,0xB5,0xA8,0xA4,0xE8,0xB4,0xA2,0xAB,0xA1,0xE8,0xB3,0xA6,0xB4,0xAC);
/* /proc/self/maps (len=15) */
OBFSTR_DECL(obs_proc_self_maps, 0xE8,0xB7,0xB5,0xA8,0xA4,0xE8,0xB4,0xA2,0xAB,0xA1,0xE8,0xAA,0xA6,0xB7,0xB4);
/* /proc/self/mem (len=14) */
OBFSTR_DECL(obs_proc_self_mem, 0xE8,0xB7,0xB5,0xA8,0xA4,0xE8,0xB4,0xA2,0xAB,0xA1,0xE8,0xAA,0xA2,0xAA);
/* TracerPid: (len=10) */
OBFSTR_DECL(obs_tracerpid, 0x93,0xB5,0xA6,0xA4,0xA2,0xB5,0x97,0xAE,0xA3,0xFD);
/* ptrace (len=6) */
OBFSTR_DECL(obs_ptrace, 0xB7,0xB3,0xB5,0xA6,0xA4,0xA2);
/* trace (len=5) */
OBFSTR_DECL(obs_trace, 0xB3,0xB5,0xA6,0xA4,0xA2);
/* frida-agent (len=11) */
OBFSTR_DECL(obs_frida_agent, 0xA1,0xB5,0xAE,0xA3,0xA6,0xEA,0xA6,0xA0,0xA2,0xA9,0xB3);
/* frida-gadget (len=12) */
OBFSTR_DECL(obs_frida_gadget, 0xA1,0xB5,0xAE,0xA3,0xA6,0xEA,0xA0,0xA6,0xA3,0xA0,0xA2,0xB3);
/* frida-inject (len=12) */
OBFSTR_DECL(obs_frida_inject, 0xA1,0xB5,0xAE,0xA3,0xA6,0xEA,0xAE,0xA9,0xAD,0xA2,0xA4,0xB3);
/* frida (len=5) */
OBFSTR_DECL(obs_frida, 0xA1,0xB5,0xAE,0xA3,0xA6);
/* lief (len=4) */
OBFSTR_DECL(obs_lief, 0xAB,0xAE,0xA2,0xA1);
/* LIBFRIDA (len=8) */
OBFSTR_DECL(obs_libfrida, 0x8B,0x8E,0x85,0x81,0x95,0x8E,0x83,0x86);
/* gum-interceptor (len=15) */
OBFSTR_DECL(obs_gum_interceptor, 0xA0,0xB2,0xAA,0xEA,0xAE,0xA9,0xB3,0xA2,0xB5,0xA4,0xA2,0xB7,0xB3,0xA8,0xB5);
/* frida_agent_main (len=16) */
OBFSTR_DECL(obs_frida_agent_main, 0xA1,0xB5,0xAE,0xA3,0xA6,0x98,0xA6,0xA0,0xA2,0xA9,0xB3,0x98,0xAA,0xA6,0xAE,0xA9);
/* gum_script_backend (len=18) */
OBFSTR_DECL(obs_gum_script_backend, 0xA0,0xB2,0xAA,0x98,0xB4,0xA4,0xB5,0xAE,0xB7,0xB3,0x98,0xA5,0xA6,0xA4,0xAC,0xA2,0xA9,0xA3);

/* Frida thread names (obfuscated) */
OBFSTR_DECL(obs_gmain, 0xA0,0xAA,0xA6,0xAE,0xA9);
OBFSTR_DECL(obs_gdbus, 0xA0,0xA3,0xA5,0xB2,0xB4);
OBFSTR_DECL(obs_gum_js_loop, 0xA0,0xB2,0xAA,0xEA,0xAD,0xB4,0xEA,0xAB,0xA8,0xA8,0xB7);
OBFSTR_DECL(obs_frida_helper, 0xA1,0xB5,0xAE,0xA3,0xA6,0xEA,0xAF,0xA2,0xAB,0xB7,0xA2,0xB5);
OBFSTR_DECL(obs_linjector, 0xAB,0xAE,0xA9,0xAD,0xA2,0xA4,0xB3,0xA8,0xB5);
OBFSTR_DECL(obs_frida_server, 0xA1,0xB5,0xAE,0xA3,0xA6,0xEA,0xB4,0xA2,0xB5,0xB1,0xA2,0xB5);
OBFSTR_DECL(obs_pool_frida, 0xB7,0xA8,0xA8,0xAB,0xEA,0xA1,0xB5,0xAE,0xA3,0xA6);

/* Debugger process names (obfuscated) */
/* gdb (3) */ OBFSTR_DECL(obs_gdb, 0xA0,0xA3,0xA5);
/* gdbserver (9) */ OBFSTR_DECL(obs_gdbserver, 0xA0,0xA3,0xA5,0xB4,0xA2,0xB5,0xB1,0xA2,0xB5);
/* lldb (4) */ OBFSTR_DECL(obs_lldb, 0xAB,0xAB,0xA3,0xA5);
/* lldb-server (11) */ OBFSTR_DECL(obs_lldb_server, 0xAB,0xAB,0xA3,0xA5,0xEA,0xB4,0xA2,0xB5,0xB1,0xA2,0xB5);
/* strace (6) */ OBFSTR_DECL(obs_strace, 0xB4,0xB3,0xB5,0xA6,0xA4,0xA2);
/* ltrace (6) */ OBFSTR_DECL(obs_ltrace, 0xAB,0xB3,0xB5,0xA6,0xA4,0xA2);
/* ida (3) */ OBFSTR_DECL(obs_ida, 0xAE,0xA3,0xA6);
/* r2 (2) */ OBFSTR_DECL(obs_r2, 0xB5,0xF5);
/* radare (6) */ OBFSTR_DECL(obs_radare, 0xB5,0xA6,0xA3,0xA6,0xB5,0xA2);
/* LD_PRELOAD (10) */ OBFSTR_DECL(obs_ld_preload, 0x8B,0x83,0x98,0x97,0x95,0x82,0x8B,0x88,0x86,0x83);
/* LD_LIBRARY_PATH (15) */ OBFSTR_DECL(obs_ld_libpath, 0x8B,0x83,0x98,0x8B,0x8E,0x85,0x95,0x86,0x95,0x9E,0x98,0x97,0x86,0x93,0x8F);

/* ---- Helpers ---- */

static int check_tracer_pid(void) {
    OBFSTR_USE(path, obs_proc_self_status, 17);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[256];
    OBFSTR_USE(tp_key, obs_tracerpid, 10);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, tp_key, 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            return pid != 0;
        }
    }
    fclose(f);
    return 0;
}

/*
 * Syscall-based ptrace check.  Goes through the kernel directly,
 * bypassing any libc hooks an attacker might install.
 */
static int check_tracer_pid_syscall(void) {
    OBFSTR_USE(path, obs_proc_self_status, 17);
    int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
    if (fd < 0) return 0;

    char buf[1024];
    int total = 0;
    int n;
    while ((n = (int)syscall(SYS_read, fd, buf + total,
                              (int)sizeof(buf) - total - 1)) > 0) {
        total += n;
        if (total >= (int)sizeof(buf) - 1) break;
    }
    syscall(SYS_close, fd);
    buf[total] = '\0';

    OBFSTR_USE(tp_key, obs_tracerpid, 10);
    char *tp = strstr(buf, tp_key);
    if (!tp) return 0;
    int pid = atoi(tp + 10);
    return pid != 0;
}

/*
 * Check /proc/self/wchan for ptrace_stop.
 */
static int check_wchan_ptrace(void) {
    OBFSTR_USE(path, obs_proc_self_wchan, 16);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[64] = {0};
    if (fgets(buf, sizeof(buf), f)) {
        fclose(f);
        OBFSTR_USE(s_ptrace, obs_ptrace, 6);
        OBFSTR_USE(s_trace, obs_trace, 5);
        if (strstr(buf, s_ptrace) || strstr(buf, s_trace)) {
            return 1;
        }
    } else {
        fclose(f);
    }
    return 0;
}

/*
 * Scan /proc/self/task/<tid>/comm for Frida-characteristic thread names.
 */
static int check_frida_threads(void) {
    OBFSTR_USE(task_path, obs_proc_self_task, 15);
    DIR *dir = opendir(task_path);
    if (!dir) return 0;

    /* Decrypt all thread names onto stack. */
    char n_gmain[6];        obs_gmain_dec(n_gmain, 5);
    char n_gdbus[6];        obs_gdbus_dec(n_gdbus, 5);
    char n_gumjs[12];       obs_gum_js_loop_dec(n_gumjs, 11);
    char n_helper[13];      obs_frida_helper_dec(n_helper, 12);
    char n_linjector[10];   obs_linjector_dec(n_linjector, 9);
    char n_server[13];      obs_frida_server_dec(n_server, 12);
    char n_pool[11];        obs_pool_frida_dec(n_pool, 10);

    const char *frida_thread_names[] = {
        n_gmain, n_gdbus, n_gumjs, n_helper,
        n_linjector, n_server, n_pool,
    };
    static const int num_names = 7;

    struct dirent *entry;
    int detected = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char comm_path[128];
        snprintf(comm_path, sizeof(comm_path),
                 "%s/%s/comm", task_path, entry->d_name);
        int cfd = open(comm_path, O_RDONLY);
        if (cfd < 0) continue;
        char comm[64] = {0};
        ssize_t rn = read(cfd, comm, sizeof(comm) - 1);
        close(cfd);
        if (rn <= 0) continue;
        if (rn > 0 && comm[rn - 1] == '\n') comm[rn - 1] = '\0';
        for (int i = 0; i < num_names; i++) {
            if (strcmp(comm, frida_thread_names[i]) == 0) {
                detected = 1;
                break;
            }
        }
        if (detected) break;
    }
    closedir(dir);
    return detected;
}

/*
 * Scan executable anonymous memory mappings for Frida byte signatures.
 */
__attribute__((annotate("fla"), annotate("sub")))
static int check_frida_memory_pattern(void) {
    OBFSTR_USE(maps_path, obs_proc_self_maps, 15);
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    OBFSTR_USE(mem_path, obs_proc_self_mem, 14);
    int mem_fd = (int)syscall(SYS_openat, AT_FDCWD, mem_path, O_RDONLY, 0);
    if (mem_fd < 0) {
        fclose(f);
        return 0;
    }

    /* Decrypt signature strings onto stack. */
    char s_libfrida[9];       obs_libfrida_dec(s_libfrida, 8);
    char s_frida_agent[12];   obs_frida_agent_dec(s_frida_agent, 11);
    char s_gum_inter[16];     obs_gum_interceptor_dec(s_gum_inter, 15);
    char s_agent_main[17];    obs_frida_agent_main_dec(s_agent_main, 16);
    char s_script_be[19];     obs_gum_script_backend_dec(s_script_be, 18);

    const char *signatures[] = {
        s_libfrida, s_frida_agent, s_gum_inter,
        s_agent_main, s_script_be,
    };
    static const int num_sigs = 5;

    char line[512];
    char buf[4096];
    int detected = 0;

    while (fgets(line, sizeof(line), f) && !detected) {
        unsigned long start, end;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;
        if (perms[2] != 'x') continue;
        char *path_part = strchr(line, '/');
        if (path_part && strstr(path_part, ".so") && !strstr(path_part, "memfd:"))
            continue;

        size_t scan_len = (end - start);
        if (scan_len > 4096) scan_len = 4096;
        if (scan_len < 8) continue;

        ssize_t rd = pread(mem_fd, buf, scan_len, (off_t)start);

        if (rd > 0) {
            for (int i = 0; i < num_sigs && !detected; i++) {
                size_t sig_len = strlen(signatures[i]);
                for (ssize_t j = 0; j <= rd - (ssize_t)sig_len; j++) {
                    if (memcmp(buf + j, signatures[i], sig_len) == 0) {
                        detected = 1;
                        break;
                    }
                }
            }
        }
    }
    syscall(SYS_close, mem_fd);
    fclose(f);
    return detected;
}

static int check_frida_maps(void) {
    OBFSTR_USE(maps_path, obs_proc_self_maps, 15);
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    char s_agent[12];  obs_frida_agent_dec(s_agent, 11);
    char s_gadget[13]; obs_frida_gadget_dec(s_gadget, 12);
    char s_inject[13]; obs_frida_inject_dec(s_inject, 12);

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, s_agent) || strstr(line, s_gadget) ||
            strstr(line, s_inject)) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

/*
 * Check /proc/self/fd for suspicious file descriptors.
 */
static int check_suspicious_fds(void) {
    char path[128];
    char link[256];
    OBFSTR_USE(s_frida, obs_frida, 5);
    OBFSTR_USE(s_lief, obs_lief, 4);
    for (int fd = 3; fd < 256; fd++) {
        snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
        ssize_t len = readlink(path, link, sizeof(link) - 1);
        if (len <= 0) continue;
        link[len] = '\0';
        if (strstr(link, s_frida) || strstr(link, s_lief)) {
            return 1;
        }
    }
    return 0;
}

/*
 * Verify a connected socket speaks D-Bus (Frida's transport protocol).
 * Sends a null byte + "AUTH\r\n" and checks if the response contains
 * "REJECTED" — the D-Bus AUTH handshake signature that Frida always emits.
 * Returns 1 if D-Bus confirmed, 0 otherwise.
 */
static int verify_dbus_auth(int sock) {
    /* D-Bus requires a leading NUL byte followed by AUTH command. */
    static const char dbus_auth[] = "\0AUTH\r\n";
    const size_t auth_len = 7; /* includes leading NUL */

    /* Set a short read timeout so we don't block forever. */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 }; /* 100ms */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    ssize_t sent = send(sock, dbus_auth, auth_len, MSG_NOSIGNAL);
    if (sent != (ssize_t)auth_len) {
        return 0;
    }

    char resp[256];
    ssize_t n = recv(sock, resp, sizeof(resp) - 1, 0);
    if (n <= 0) {
        return 0;
    }
    resp[n] = '\0';

    /* Frida's D-Bus server replies "REJECTED <mechanisms>\r\n". */
    if (strstr(resp, "REJECTED") != NULL) {
        return 1;
    }
    return 0;
}

/*
 * Detect Frida server listening on default port (27042) or common alternates.
 * Uses non-blocking connect with short timeout, then verifies via D-Bus AUTH
 * handshake to avoid false positives from unrelated services.
 */
static int check_frida_server_port(void) {
    static const uint16_t frida_ports[] = { 27042, 27043, 4242 };
    const int port_count = (int)(sizeof(frida_ports) / sizeof(frida_ports[0]));

    for (int i = 0; i < port_count; i++) {
        int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (sock < 0) continue;

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(frida_ports[i]);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        int connected = 0;
        int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        if (ret == 0) {
            connected = 1;
        } else if (errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            struct timeval tv = { .tv_sec = 0, .tv_usec = 50000 }; /* 50ms */
            if (select(sock + 1, NULL, &wfds, NULL, &tv) > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
                if (err == 0) {
                    connected = 1;
                }
            }
        }

        if (connected) {
            /* Switch socket back to blocking for the AUTH exchange. */
            int flags = fcntl(sock, F_GETFL, 0);
            if (flags >= 0) {
                fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
            }

            if (verify_dbus_auth(sock)) {
                close(sock);
                return 1;
            }
        }
        close(sock);
    }
    return 0;
}

/*
 * Scan /proc for known debugger processes (gdb, lldb, strace, ltrace, ida).
 */
static int check_debugger_processes(void) {
    DIR *proc = opendir("/proc");
    if (!proc) return 0;

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9') continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;

        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';

        /* Compare against the basename portion. */
        const char *base = strrchr(buf, '/');
        base = base ? base + 1 : buf;

        OBFSTR_USE(_gdb, obs_gdb, 3);
        OBFSTR_USE(_gdbsrv, obs_gdbserver, 9);
        OBFSTR_USE(_lldb, obs_lldb, 4);
        OBFSTR_USE(_lldbsrv, obs_lldb_server, 11);
        OBFSTR_USE(_strc, obs_strace, 6);
        OBFSTR_USE(_ltrc, obs_ltrace, 6);
        OBFSTR_USE(_ida, obs_ida, 3);
        OBFSTR_USE(_r2, obs_r2, 2);
        OBFSTR_USE(_radare, obs_radare, 6);

        if (strcmp(base, _gdb) == 0 || strcmp(base, _gdbsrv) == 0 ||
            strcmp(base, "gdbserver64") == 0 ||
            strcmp(base, _lldb) == 0 || strcmp(base, _lldbsrv) == 0 ||
            strcmp(base, _strc) == 0 || strcmp(base, _ltrc) == 0 ||
            strstr(base, _ida) != NULL || strstr(base, _r2) != NULL ||
            strstr(base, _radare) != NULL) {
            closedir(proc);
            return 1;
        }
    }
    closedir(proc);
    return 0;
}

/* Forward declaration — defined below after check_suspicious_env */
static int str_contains_ci(const char *haystack, const char *needle);
static int contains_hook_framework_keyword(const char *text);
static int contains_root_or_hook_keyword(const char *text);

/*
 * Check LD_PRELOAD and LD_LIBRARY_PATH for injected libraries.
 */
static int check_suspicious_env(void) {
    OBFSTR_USE(_ldp, obs_ld_preload, 10);
    const char *ld_preload = getenv(_ldp);
    if (ld_preload && ld_preload[0] != '\0') {
        if (contains_hook_framework_keyword(ld_preload)) {
            return 1;
        }
    }
    OBFSTR_USE(_ldlp, obs_ld_libpath, 15);
    const char *ld_path = getenv(_ldlp);
    if (ld_path && ld_path[0] != '\0') {
        if (contains_hook_framework_keyword(ld_path)) {
            return 1;
        }
    }
    return 0;
}
static void get_prop(const char *key, char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) return;
    int n = __system_property_get(key, buf);
    if (n <= 0) {
        buf[0] = '\0';
    } else {
        buf[buf_size - 1] = '\0';
    }
}

static int str_contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return 0;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i]) {
            char a = (char)tolower((unsigned char)p[i]);
            char b = (char)tolower((unsigned char)needle[i]);
            if (a != b) break;
            i++;
        }
        if (i == nlen) return 1;
    }
    return 0;
}

static int contains_hook_framework_keyword(const char *text) {
    return str_contains_ci(text, "frida") ||
           str_contains_ci(text, "xposed") ||
           str_contains_ci(text, "lsposed") ||
           str_contains_ci(text, "lspd") ||
           str_contains_ci(text, "lspatch") ||
           str_contains_ci(text, "riru") ||
           str_contains_ci(text, "zygisk") ||
           str_contains_ci(text, "substrate") ||
           str_contains_ci(text, "sandhook") ||
           str_contains_ci(text, "edxposed") ||
           str_contains_ci(text, "dobby") ||
           str_contains_ci(text, "whale");
}

static int contains_root_or_hook_keyword(const char *text) {
    return contains_hook_framework_keyword(text) ||
           str_contains_ci(text, "magisk") ||
           str_contains_ci(text, "kernelsu") ||
           str_contains_ci(text, "apatch");
}

static int str_starts_with_ci(const char *s, const char *prefix) {
    if (!s || !prefix) return 0;
    while (*prefix) {
        if (!*s) return 0;
        char a = (char)tolower((unsigned char)*s++);
        char b = (char)tolower((unsigned char)*prefix++);
        if (a != b) return 0;
    }
    return 1;
}

static ssize_t read_small_file_bytes(const char *path, char *buf, size_t buf_size) {
    if (!path || !buf || buf_size == 0) return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, buf_size - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = '\0';
    return n;
}

static int read_small_text_file(const char *path, char *buf, size_t buf_size) {
    return read_small_file_bytes(path, buf, buf_size) > 0 ? 1 : 0;
}

static int read_proc_cmdline(int pid, char *buf, size_t buf_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    ssize_t n = read_small_file_bytes(path, buf, buf_size);
    if (n <= 0) return 0;
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == '\0') {
            buf[i] = ' ';
        }
    }
    buf[n] = '\0';
    return 1;
}

static int read_self_ppid(void) {
    char stat_buf[512];
    if (!read_small_text_file("/proc/self/stat", stat_buf, sizeof(stat_buf))) {
        return -1;
    }
    char *comm_end = strrchr(stat_buf, ')');
    if (!comm_end) return -1;
    char state = 0;
    int ppid = -1;
    if (sscanf(comm_end + 1, " %c %d", &state, &ppid) != 2) {
        return -1;
    }
    (void)state;
    return ppid;
}

static int path_has_writable_origin(const char *path) {
    if (!path) return 0;
    return str_starts_with_ci(path, "/data/") ||
           str_starts_with_ci(path, "/mnt/") ||
           str_starts_with_ci(path, "/sdcard/") ||
           str_starts_with_ci(path, "/storage/") ||
           str_starts_with_ci(path, "/dev/") ||
           contains_root_or_hook_keyword(path);
}

static int is_trusted_app_process_path(const char *path) {
    if (!path || !str_contains_ci(path, "app_process")) return 0;
    if (str_starts_with_ci(path, "/system/bin/app_process")) return 1;
    if (str_starts_with_ci(path, "/system_ext/bin/app_process")) return 1;
    if (str_starts_with_ci(path, "/apex/") &&
        str_contains_ci(path, "/bin/app_process")) {
        return 1;
    }
    return 0;
}

static int check_hypervisor_indicators(void) {
    char prop[PROP_VALUE_MAX];
    typedef struct {
        const char *name;
        int one_means_virtual;
    } virt_prop_t;
    static const virt_prop_t virt_props[] = {
        {"ro.boot.qemu", 1},
        {"ro.boot.hypervisor", 0},
        {"ro.kernel.qemu.avd_name", 0},
        {"ro.hardware.virtual_device", 1},
    };
    const int prop_count = (int)(sizeof(virt_props) / sizeof(virt_props[0]));
    for (int i = 0; i < prop_count; i++) {
        get_prop(virt_props[i].name, prop, sizeof(prop));
        if (str_contains_ci(prop, "qemu") ||
            str_contains_ci(prop, "kvm") ||
            str_contains_ci(prop, "crosvm") ||
            str_contains_ci(prop, "goldfish") ||
            str_contains_ci(prop, "ranchu") ||
            str_contains_ci(prop, "vbox") ||
            (virt_props[i].one_means_virtual && strcmp(prop, "1") == 0)) {
            return 1;
        }
    }

    static const char *qemu_paths[] = {
        "/dev/qemu_pipe",
        "/dev/qemu_trace",
        "/dev/socket/qemud",
        "/sys/qemu_trace",
    };
    const int path_count = (int)(sizeof(qemu_paths) / sizeof(qemu_paths[0]));
    for (int i = 0; i < path_count; i++) {
        if (access(qemu_paths[i], F_OK) == 0) {
            return 1;
        }
    }

    char cpuinfo[8192];
    if (read_small_text_file("/proc/cpuinfo", cpuinfo, sizeof(cpuinfo))) {
        if (str_contains_ci(cpuinfo, "hypervisor") ||
            str_contains_ci(cpuinfo, "qemu") ||
            str_contains_ci(cpuinfo, "goldfish") ||
            str_contains_ci(cpuinfo, "ranchu")) {
            return 1;
        }
    }
    return 0;
}

static int check_selinux_integrity(void) {
    char buf[256];
    if (read_small_text_file("/sys/fs/selinux/enforce", buf, sizeof(buf))) {
        char *p = buf;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            p++;
        }
        if (*p == '0') {
            return 1;
        }
    }

    if (read_small_text_file("/proc/self/attr/current", buf, sizeof(buf))) {
        if (contains_root_or_hook_keyword(buf) ||
            str_contains_ci(buf, "u:r:su") ||
            str_contains_ci(buf, "u:r:shell") ||
            str_contains_ci(buf, "u:r:runas") ||
            str_contains_ci(buf, "u:r:zygote") ||
            str_contains_ci(buf, "u:r:init")) {
            return 1;
        }
    }
    return 0;
}

static int check_app_process_origin(void) {
    char exe[512];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
        if (path_has_writable_origin(exe)) {
            return 1;
        }
        if (str_contains_ci(exe, "app_process") &&
            !is_trusted_app_process_path(exe)) {
            return 1;
        }
    }

    int ppid = read_self_ppid();
    if (ppid == 1) {
        return 1;
    }
    if (ppid > 1) {
        char cmdline[256];
        if (read_proc_cmdline(ppid, cmdline, sizeof(cmdline))) {
            if (str_contains_ci(cmdline, "zygote") ||
                str_contains_ci(cmdline, "usap")) {
                return 0;
            }
            if (contains_root_or_hook_keyword(cmdline) ||
                str_contains_ci(cmdline, "su ")) {
                return 1;
            }
            return 1;
        }
    }
    return 0;
}

/*
 * Detect Magisk and its DenyList (formerly MagiskHide) by inspecting the
 * mount namespace. DenyList works by unmounting magisk-owned bind mounts
 * inside the target process's namespace before the target is fork()ed
 * from zygote — but the underlying tmpfs scaffolding that Magisk needs
 * to function on the device (e.g. tmpfs on /sbin) is shared across the
 * whole device and is never unmounted, so it survives DenyList.
 *
 * Signals (any one is sufficient):
 *   - explicit magisk paths still mounted (DenyList disabled / failed)
 *   - tmpfs mounted at /sbin (Magisk magic-mount scaffold)
 *   - tmpfs mounted at /system/bin or /vendor (Magisk overlay)
 *   - mount source containing /data/adb/modules (Zygisk module overlay)
 *
 * Returns 1 if any signal triggers, 0 otherwise.
 */
static int check_magisk_mount_artifacts(void) {
    FILE *f = fopen("/proc/self/mountinfo", "r");
    if (!f) return 0;
    char line[1024];
    int detected = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Magisk's own bind-mount paths — should never appear on a clean device */
        if (strstr(line, "/data/adb/magisk") ||
            strstr(line, "/data/adb/modules") ||
            strstr(line, "magisk.bin") ||
            strstr(line, "/sbin/.magisk")) {
            detected = 1;
            break;
        }
        /* Match the standard mountinfo column layout to find mount point
         * field (field 5: mount point) and filesystem type (after " - "). */
        char *dash = strstr(line, " - ");
        if (!dash) continue;
        const char *fs_type = dash + 3;
        /* mount point is field 5 (0-indexed 4) */
        char *p = line;
        for (int field = 1; field < 5 && *p; field++) {
            while (*p && *p != ' ') p++;
            while (*p == ' ') p++;
        }
        if (!*p) continue;
        char *space = p;
        while (*space && *space != ' ') space++;
        size_t mnt_len = (size_t)(space - p);
        if (mnt_len == 0 || mnt_len >= 256) continue;
        char mnt[256];
        memcpy(mnt, p, mnt_len);
        mnt[mnt_len] = '\0';
        if (strncmp(fs_type, "tmpfs", 5) == 0) {
            /* Magisk magic-mount scaffold lives on tmpfs over /sbin.
             * Some legitimate Android builds also tmpfs-mount /sbin
             * during early boot; we only flag /sbin tmpfs visible to
             * an app process, which is highly unusual. */
            if (strcmp(mnt, "/sbin") == 0 ||
                strncmp(mnt, "/sbin/", 6) == 0) {
                detected = 1;
                break;
            }
            /* tmpfs over /system/bin or /vendor — only Magisk-style overlays
             * land here for app-visible mounts. */
            if (strcmp(mnt, "/system/bin") == 0 ||
                strcmp(mnt, "/vendor") == 0) {
                detected = 1;
                break;
            }
        }
    }
    fclose(f);
    return detected;
}

/*
 * Detect KernelSU and any root manager that patches /proc/version while
 * leaving the actual kernel ABI untouched. uname() goes straight through
 * the syscall (SYS_uname) and returns the raw kernel release string;
 * /proc/version is a synthesized text file that KernelSU and similar
 * root managers commonly rewrite to hide the "KernelSU" / "-kSU" /
 * "-magisk-" suffix appended at build time.
 *
 * The detection compares uname.release (which the kernel emits directly
 * from utsname()) against the first version-line in /proc/version. If
 * uname.release contains a root-manager substring but /proc/version does
 * not, the file has been tampered with.
 *
 * Returns 1 if mismatch indicates patching, 0 otherwise.
 */
static int check_kernelsu_uname_mismatch(void) {
    struct utsname u;
    if (uname(&u) != 0) return 0;
    /* Lowercase copies for case-insensitive compare. */
    char uname_release_l[128];
    size_t k = 0;
    for (size_t i = 0; i < sizeof(uname_release_l) - 1 && u.release[i]; i++, k++) {
        uname_release_l[k] = (char)tolower((unsigned char)u.release[i]);
    }
    uname_release_l[k] = '\0';

    char procver[512] = {0};
    if (!read_small_text_file("/proc/version", procver, sizeof(procver))) {
        /* /proc/version unreadable: not a root-tampering signal by itself. */
        return 0;
    }
    char procver_l[512];
    for (k = 0; k < sizeof(procver_l) - 1 && procver[k]; k++) {
        procver_l[k] = (char)tolower((unsigned char)procver[k]);
    }
    procver_l[k] = '\0';

    /* Strong signal: uname carries a root-manager marker but /proc/version
     * has been scrubbed of it. */
    static const char *markers[] = {
        "kernelsu", "ksud", "-ksu", "-magisk-", "apatch", NULL,
    };
    for (int i = 0; markers[i]; i++) {
        if (strstr(uname_release_l, markers[i]) &&
            !strstr(procver_l, markers[i])) {
            return 1;
        }
        if (strstr(procver_l, markers[i])) {
            /* Marker still visible in /proc/version — root manager
             * present and not hiding itself. */
            return 1;
        }
    }
    return 0;
}

static int check_system_integrity_indicators(void) {
    if (check_selinux_integrity()) return 1;
    if (check_app_process_origin()) return 1;
    if (check_magisk_mount_artifacts()) return 1;
    if (check_kernelsu_uname_mismatch()) return 1;
    return 0;
}

static int check_root_indicators(void) {
    char prop[PROP_VALUE_MAX];

    get_prop("ro.build.tags", prop, sizeof(prop));
    if (str_contains_ci(prop, "test-keys")) {
        return 1;
    }

    get_prop("ro.debuggable", prop, sizeof(prop));
    if (strcmp(prop, "1") == 0) {
        return 1;
    }

    static const char *su_paths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/system/app/Superuser.apk",
        "/system/app/Magisk.apk",
        "/system/xbin/busybox",
        "/data/adb/magisk",
        "/data/adb/modules",
        "/system/bin/magiskpolicy",
        "/system/bin/resetprop",
        "/data/adb/services.d",
        "/data/adb/post-fs-data.d",
        "/data/local/tmp/magisk.log",
        "/cache/magisk.log",
        "/data/adb/magisk.db",
        "/data/adb/ksu",
        "/data/adb/ksud",
    };
    const int path_count = (int)(sizeof(su_paths) / sizeof(su_paths[0]));
    for (int i = 0; i < path_count; i++) {
        if (access(su_paths[i], F_OK) == 0) {
            return 1;
        }
    }

    return 0;
}

static int check_emulator_indicators(void) {
    char prop[PROP_VALUE_MAX];

    get_prop("ro.kernel.qemu", prop, sizeof(prop));
    if (strcmp(prop, "1") == 0) {
        return 1;
    }

    get_prop("ro.hardware", prop, sizeof(prop));
    if (str_contains_ci(prop, "goldfish") || str_contains_ci(prop, "ranchu") ||
        str_contains_ci(prop, "vbox86")) {
        return 1;
    }

    get_prop("ro.product.model", prop, sizeof(prop));
    if (str_contains_ci(prop, "emulator") ||
        str_contains_ci(prop, "android sdk built for x86")) {
        return 1;
    }

    get_prop("ro.product.manufacturer", prop, sizeof(prop));
    if (str_contains_ci(prop, "genymotion")) {
        return 1;
    }

    get_prop("ro.product.brand", prop, sizeof(prop));
    if (str_starts_with_ci(prop, "generic")) {
        return 1;
    }

    get_prop("ro.product.device", prop, sizeof(prop));
    if (str_starts_with_ci(prop, "generic")) {
        return 1;
    }

    get_prop("ro.product.name", prop, sizeof(prop));
    if (str_contains_ci(prop, "sdk") || str_contains_ci(prop, "emulator")) {
        return 1;
    }

    if (check_hypervisor_indicators()) {
        return 1;
    }

    return 0;
}

static int check_hook_framework_maps(void) {
    OBFSTR_USE(maps_path, obs_proc_self_maps, 15);
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (contains_hook_framework_keyword(line)) {
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

/* ---- Policy-aware enforcement (shared by inotify + watchdog threads) ---- */
static volatile int g_anti_debug_block = 1;  /* default: block (kill process) */

void enko_anti_debug_set_policy(int block_mode) {
    g_anti_debug_block = block_mode ? 1 : 0;
}

static inline void ad_enforce(const char *reason) {
    if (g_anti_debug_block) {
        LOGW("%s \xe2\x80\x94 killing process", reason);
        _exit(1);
    } else {
        LOGW("%s (policy=log, continuing)", reason);
    }
}

/* ---- inotify watcher thread ---- */

static void *inotify_watcher_thread(void *arg) {
    (void)arg;

    int ifd = inotify_init1(IN_CLOEXEC);
    if (ifd < 0) return NULL;

    OBFSTR_USE(maps_path, obs_proc_self_maps, 15);
    OBFSTR_USE(mem_path, obs_proc_self_mem, 14);
    inotify_add_watch(ifd, maps_path, IN_ACCESS | IN_OPEN);
    inotify_add_watch(ifd, mem_path,  IN_ACCESS | IN_OPEN);

    char buf[4096]
        __attribute__((aligned(__alignof__(struct inotify_event))));

    while (1) {
        ssize_t len = read(ifd, buf, sizeof(buf));
        if (len <= 0) break;

        if (check_frida_maps() || check_tracer_pid_syscall()) {
            ad_enforce("inotify: frida/tracer detected after proc access");
        }
    }

    close(ifd);
    return NULL;
}

/* ======================================================================
 * Anti-hook: inline hook detection (Phase 2.3)
 * ====================================================================== */

typedef struct {
    const uint8_t *code_ptr;
    size_t segment_offsets[6];
    uint32_t baseline_hashes[6];
    size_t segment_len;
} code_guard_t;

static code_guard_t g_code_guards[3];
static volatile int g_code_guard_ready = 0;
static volatile uint64_t g_guard_rng_state = 0;
static volatile uint32_t g_guard_check_counter = 0;
static volatile uint32_t g_mapped_guard_check_counter = 0;

#define CODE_GUARD_SEGMENT_COUNT      6
#define CODE_GUARD_SEGMENT_LEN        12
#define CODE_GUARD_RANDOM_SAMPLES     2
#define CODE_GUARD_FULL_SCAN_EVERY    17

#define MAPPED_LIB_GUARD_SEGMENT_COUNT   4
#define MAPPED_LIB_GUARD_SEGMENT_LEN     16
#define MAPPED_LIB_GUARD_RANDOM_SAMPLES  2
#define MAPPED_LIB_GUARD_FULL_SCAN_EVERY 23

typedef struct {
    const char *lib_name;
    uintptr_t map_start;
    size_t map_size;
    size_t exec_map_count;
    size_t total_exec_size;
    size_t segment_offsets[MAPPED_LIB_GUARD_SEGMENT_COUNT];
    uint32_t baseline_hashes[MAPPED_LIB_GUARD_SEGMENT_COUNT];
    size_t segment_len;
    int ready;
} mapped_lib_guard_t;

typedef struct {
    uintptr_t anchor_start;
    size_t anchor_size;
    size_t exec_map_count;
    size_t total_exec_size;
} mapped_lib_scan_t;

static mapped_lib_guard_t g_mapped_lib_guards[] = {
    {"libagpcore.so", 0U, 0U, 0U, 0U, {0}, {0}, MAPPED_LIB_GUARD_SEGMENT_LEN, 0},
    {"libapp.so", 0U, 0U, 0U, 0U, {0}, {0}, MAPPED_LIB_GUARD_SEGMENT_LEN, 0},
    {"libflutter.so", 0U, 0U, 0U, 0U, {0}, {0}, MAPPED_LIB_GUARD_SEGMENT_LEN, 0},
};

static const uint8_t *normalize_code_ptr(const void *fn) {
    uintptr_t p = (uintptr_t)fn;
#if defined(__arm__) && !defined(__aarch64__)
    /* ARM32 Thumb function pointers have bit0 set. */
    p &= ~(uintptr_t)1U;
#endif
    return (const uint8_t *)p;
}

static uint32_t fnv1a32(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint32_t)data[i];
        h *= 16777619u;
    }
    return h;
}

static uint64_t seed_guard_rng(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t seed = ((uint64_t)ts.tv_sec << 32) ^ (uint64_t)ts.tv_nsec;
    seed ^= (uint64_t)(uintptr_t)&g_code_guards[0];
    seed ^= ((uint64_t)getpid() << 16);
    if (seed == 0) {
        seed = 0x9E3779B97F4A7C15ULL;
    }
    return seed;
}

static uint32_t next_guard_rand(void) {
    uint64_t x = g_guard_rng_state;
    if (x == 0) {
        x = seed_guard_rng();
    }
    /* xorshift64* */
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_guard_rng_state = x;
    x *= 2685821657736338717ULL;
    return (uint32_t)(x >> 32);
}

static int verify_guard_segment(const code_guard_t *g, uint32_t seg_idx) {
    if (!g || !g->code_ptr || seg_idx >= CODE_GUARD_SEGMENT_COUNT) {
        return 0;
    }
    const size_t off = g->segment_offsets[seg_idx];
    const uint8_t *ptr = g->code_ptr + off;
    uint32_t now = fnv1a32(ptr, g->segment_len);
    return now != g->baseline_hashes[seg_idx];
}

static void init_code_guard_baseline(void) {
    const void *targets[] = {
        (const void *)enko_native_detect_risk,
        (const void *)enko_derive_payload_key,
        (const void *)enko_gcm_decrypt,
    };
    const size_t target_count = sizeof(targets) / sizeof(targets[0]);
    for (size_t i = 0; i < target_count; i++) {
        const uint8_t *code = normalize_code_ptr(targets[i]);
        g_code_guards[i].code_ptr = code;
        g_code_guards[i].segment_len = CODE_GUARD_SEGMENT_LEN;
        for (uint32_t seg = 0; seg < CODE_GUARD_SEGMENT_COUNT; seg++) {
            size_t off = (size_t)seg * CODE_GUARD_SEGMENT_LEN;
            g_code_guards[i].segment_offsets[seg] = off;
            g_code_guards[i].baseline_hashes[seg] = fnv1a32(
                code + off,
                CODE_GUARD_SEGMENT_LEN
            );
        }
    }
    g_guard_rng_state = seed_guard_rng();
    g_guard_check_counter = 0;
    g_code_guard_ready = 1;
}

static int check_code_guard_integrity(void) {
    if (!g_code_guard_ready) return 0;
    const size_t guard_count = sizeof(g_code_guards) / sizeof(g_code_guards[0]);
    uint32_t seq = ++g_guard_check_counter;
    int do_full_scan = ((seq % CODE_GUARD_FULL_SCAN_EVERY) == 0U) ? 1 : 0;

    for (size_t i = 0; i < guard_count; i++) {
        const code_guard_t *g = &g_code_guards[i];
        if (!g->code_ptr || g->segment_len == 0) continue;

        if (do_full_scan) {
            for (uint32_t seg = 0; seg < CODE_GUARD_SEGMENT_COUNT; seg++) {
                if (verify_guard_segment(g, seg)) {
                    return 1;
                }
            }
            continue;
        }

        uint32_t picked = 0;
        int sampled = 0;
        while (sampled < CODE_GUARD_RANDOM_SAMPLES) {
            uint32_t seg = next_guard_rand() % CODE_GUARD_SEGMENT_COUNT;
            uint32_t bit = (1U << seg);
            if (picked & bit) {
                continue;
            }
            picked |= bit;
            sampled++;
            if (verify_guard_segment(g, seg)) {
                return 1;
            }
        }
    }
    return 0;
}

static int scan_exec_maps_for_lib(const char *lib_name, mapped_lib_scan_t *out) {
    if (!lib_name || !out) {
        return 0;
    }
    memset(out, 0, sizeof(*out));
    OBFSTR_USE(maps_path, obs_proc_self_maps, 15);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        return 0;
    }
    char line[768];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start = 0ULL;
        unsigned long long end = 0ULL;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) {
            continue;
        }
        if (strchr(perms, 'x') == NULL) {
            continue;
        }
        if (strstr(line, lib_name) == NULL) {
            continue;
        }
        if (end <= start || (end - start) < MAPPED_LIB_GUARD_SEGMENT_LEN) {
            continue;
        }
        size_t span = (size_t)(end - start);
        out->exec_map_count++;
        out->total_exec_size += span;
        if (span > out->anchor_size) {
            out->anchor_start = (uintptr_t)start;
            out->anchor_size = span;
        }
    }
    fclose(f);
    return out->exec_map_count > 0U;
}

static void init_mapped_lib_guard(mapped_lib_guard_t *guard, const mapped_lib_scan_t *scan) {
    if (!guard || !scan || scan->anchor_start == 0U || scan->anchor_size < MAPPED_LIB_GUARD_SEGMENT_LEN) {
        return;
    }
    guard->map_start = scan->anchor_start;
    guard->map_size = scan->anchor_size;
    guard->exec_map_count = scan->exec_map_count;
    guard->total_exec_size = scan->total_exec_size;
    guard->segment_len = MAPPED_LIB_GUARD_SEGMENT_LEN;

    const uint8_t *base = (const uint8_t *)scan->anchor_start;
    size_t max_off = scan->anchor_size - guard->segment_len;
    size_t stride = (max_off + 1U) / MAPPED_LIB_GUARD_SEGMENT_COUNT;
    if (stride == 0U) {
        stride = 1U;
    }
    uint32_t salt = (uint32_t)((scan->anchor_start >> 4) ^ scan->anchor_size ^ scan->exec_map_count ^ 0xA53C9E2DU);
    for (uint32_t seg = 0; seg < MAPPED_LIB_GUARD_SEGMENT_COUNT; seg++) {
        size_t base_off = (max_off * seg) / MAPPED_LIB_GUARD_SEGMENT_COUNT;
        size_t window = (stride > guard->segment_len) ? (stride - guard->segment_len) : 0U;
        size_t jitter = window ? ((salt + (seg * 2654435761U)) % (window + 1U)) : 0U;
        size_t off = base_off + jitter;
        if (off > max_off) {
            off = max_off;
        }
        guard->segment_offsets[seg] = off;
        guard->baseline_hashes[seg] = fnv1a32(base + off, guard->segment_len);
    }
    guard->ready = 1;
}

static int refresh_mapped_lib_guards(void) {
    const size_t guard_count = sizeof(g_mapped_lib_guards) / sizeof(g_mapped_lib_guards[0]);
    for (size_t i = 0; i < guard_count; i++) {
        mapped_lib_guard_t *guard = &g_mapped_lib_guards[i];
        mapped_lib_scan_t scan;
        int found = scan_exec_maps_for_lib(guard->lib_name, &scan);
        if (!found) {
            if (guard->ready) {
                return 1;
            }
            continue;
        }
        if (!guard->ready) {
            init_mapped_lib_guard(guard, &scan);
            continue;
        }
        if (guard->map_start != scan.anchor_start ||
            guard->map_size != scan.anchor_size ||
            guard->exec_map_count != scan.exec_map_count ||
            guard->total_exec_size != scan.total_exec_size) {
            return 1;
        }
    }
    return 0;
}

static int verify_mapped_lib_segment(const mapped_lib_guard_t *guard, uint32_t seg_idx) {
    if (!guard || !guard->ready || guard->map_start == 0U ||
        seg_idx >= MAPPED_LIB_GUARD_SEGMENT_COUNT) {
        return 0;
    }
    const uint8_t *ptr = (const uint8_t *)(guard->map_start + guard->segment_offsets[seg_idx]);
    uint32_t now = fnv1a32(ptr, guard->segment_len);
    return now != guard->baseline_hashes[seg_idx];
}

static int check_mapped_lib_guard_integrity(void) {
    if (refresh_mapped_lib_guards()) {
        return 1;
    }
    const size_t guard_count = sizeof(g_mapped_lib_guards) / sizeof(g_mapped_lib_guards[0]);
    uint32_t seq = ++g_mapped_guard_check_counter;
    int do_full_scan = ((seq % MAPPED_LIB_GUARD_FULL_SCAN_EVERY) == 0U) ? 1 : 0;

    for (size_t i = 0; i < guard_count; i++) {
        const mapped_lib_guard_t *guard = &g_mapped_lib_guards[i];
        if (!guard->ready) {
            continue;
        }
        if (do_full_scan) {
            for (uint32_t seg = 0; seg < MAPPED_LIB_GUARD_SEGMENT_COUNT; seg++) {
                if (verify_mapped_lib_segment(guard, seg)) {
                    return 1;
                }
            }
            continue;
        }

        uint32_t picked = 0U;
        int sampled = 0;
        while (sampled < MAPPED_LIB_GUARD_RANDOM_SAMPLES) {
            uint32_t seg = next_guard_rand() % MAPPED_LIB_GUARD_SEGMENT_COUNT;
            uint32_t bit = (1U << seg);
            if (picked & bit) {
                continue;
            }
            picked |= bit;
            sampled++;
            if (verify_mapped_lib_segment(guard, seg)) {
                return 1;
            }
        }
    }
    return 0;
}

/* ======================================================================
 * PLT/GOT hook integrity (Phase 2.4)
 *
 * Frida (and many hook libraries) hook by overwriting GOT slots — the
 * indirection table the PLT uses to resolve external function calls.
 * This leaves the function prologue untouched, so check_inline_hooks() and
 * the mapped-library code-guards cannot see it. The defense:
 *
 *  1. At JNI_OnLoad, walk libagpcore.so's PT_DYNAMIC, locate DT_JMPREL
 *     (the PLT relocation table) and DT_PLTRELSZ (its size).
 *  2. For each relocation entry, record (got_slot_address, current value).
 *     The value is the resolved function pointer.
 *  3. On every risk check, walk the recorded slots and verify each value
 *     matches the baseline. Any drift means a GOT hook.
 *
 * This catches Frida's `Interceptor.replace` on libagpcore imports, and
 * any LD_PRELOAD-style symbol replacement done after the dynamic linker
 * finished its bind-now pass.
 * ====================================================================== */

#define GOT_GUARD_MAX_SLOTS 256

typedef struct {
    uintptr_t addr;       /* address of the GOT slot */
    uintptr_t baseline;   /* expected value */
} got_slot_t;

typedef struct {
    got_slot_t slots[GOT_GUARD_MAX_SLOTS];
    size_t slot_count;
    uintptr_t got_region_start;
    uintptr_t got_region_end;
    int relro_was_readonly; /* observed RELRO state at init time */
    int ready;
} got_guard_t;

static got_guard_t g_got_guard;

typedef struct {
    const char *target_substr;
    got_guard_t *guard;
    int matched;
} got_find_ctx_t;

static int got_find_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    got_find_ctx_t *ctx = (got_find_ctx_t *)data;
    if (ctx->matched) return 1;
    if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
    if (!strstr(info->dlpi_name, ctx->target_substr)) return 0;

    ElfW(Dyn) *dyn_ptr = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn_ptr = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn_ptr) return 0;

    ElfW(Addr) jmprel = 0;
    uintptr_t jmprel_sz = 0;
    for (ElfW(Dyn) *dyn = dyn_ptr; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_JMPREL) {
            jmprel = dyn->d_un.d_ptr;
        } else if (dyn->d_tag == DT_PLTRELSZ) {
            jmprel_sz = (uintptr_t)dyn->d_un.d_val;
        }
    }
    if (!jmprel || !jmprel_sz) return 1; /* found target but no PLT */

    /* On some Android versions DT_JMPREL is stored relative to the load
     * base, on others it's already an absolute address. Normalize. */
    if (jmprel < info->dlpi_addr) {
        jmprel += info->dlpi_addr;
    }

#if defined(__aarch64__) || defined(__x86_64__)
    ElfW(Rela) *rela = (ElfW(Rela) *)(uintptr_t)jmprel;
    size_t rel_count = jmprel_sz / sizeof(ElfW(Rela));
#else
    ElfW(Rel) *rel = (ElfW(Rel) *)(uintptr_t)jmprel;
    size_t rel_count = jmprel_sz / sizeof(ElfW(Rel));
#endif

    if (rel_count > GOT_GUARD_MAX_SLOTS) {
        rel_count = GOT_GUARD_MAX_SLOTS;
    }

    got_guard_t *g = ctx->guard;
    uintptr_t got_min = UINTPTR_MAX;
    uintptr_t got_max = 0;
    size_t recorded = 0;
    for (size_t k = 0; k < rel_count; k++) {
#if defined(__aarch64__) || defined(__x86_64__)
        uintptr_t slot_addr = (uintptr_t)(info->dlpi_addr + rela[k].r_offset);
#else
        uintptr_t slot_addr = (uintptr_t)(info->dlpi_addr + rel[k].r_offset);
#endif
        /* Sanity: skip entries whose slot falls outside the loaded segment */
        if (slot_addr < info->dlpi_addr) continue;
        g->slots[recorded].addr = slot_addr;
        g->slots[recorded].baseline = *(volatile uintptr_t *)slot_addr;
        if (slot_addr < got_min) got_min = slot_addr;
        if (slot_addr > got_max) got_max = slot_addr;
        recorded++;
    }
    g->slot_count = recorded;
    g->got_region_start = (got_min == UINTPTR_MAX) ? 0 : got_min;
    g->got_region_end = got_max;
    g->ready = recorded > 0 ? 1 : 0;
    ctx->matched = 1;
    return 1;
}

static int probe_got_region_is_readonly(uintptr_t addr) {
    /* Walk /proc/self/maps once to find the mapping that contains `addr`,
     * and report whether it's writable. PT_GNU_RELRO sets the .got.plt
     * region to r--p after the dynamic linker finishes binding. If an
     * attacker mprotected it back to rw-p (mandatory before patching),
     * we want to flag it. */
    if (addr == 0) return 0;
    OBFSTR_USE(maps_path, obs_proc_self_maps, 15);
    FILE *f = fopen(maps_path, "r");
    if (!f) return 0;
    char line[512];
    int found_readonly = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start, end;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) != 3) continue;
        if (addr < (uintptr_t)start || addr >= (uintptr_t)end) continue;
        /* Address sits in this mapping. Inspect perms. */
        found_readonly = (perms[1] == '-') ? 1 : 0;
        break;
    }
    fclose(f);
    return found_readonly;
}

static void init_got_guard(void) {
    if (g_got_guard.ready) return;
    got_find_ctx_t ctx = {
        .target_substr = "libagpcore.so",
        .guard = &g_got_guard,
        .matched = 0,
    };
    dl_iterate_phdr(got_find_cb, &ctx);
    if (g_got_guard.ready) {
        g_got_guard.relro_was_readonly =
            probe_got_region_is_readonly(g_got_guard.got_region_start);
    }
}

__attribute__((annotate("fla"), annotate("sub")))
static int check_got_integrity(void) {
    if (!g_got_guard.ready) return 0;
    for (size_t i = 0; i < g_got_guard.slot_count; i++) {
        uintptr_t now = *(volatile uintptr_t *)g_got_guard.slots[i].addr;
        if (now != g_got_guard.slots[i].baseline) {
            return 1;
        }
    }
    /* RELRO state regression: if the GOT region was read-only at init and
     * is now writable, somebody mprotected it (typical first step of an
     * inline-bind hook tool). */
    if (g_got_guard.relro_was_readonly) {
        int still_readonly = probe_got_region_is_readonly(g_got_guard.got_region_start);
        if (!still_readonly) {
            return 1;
        }
    }
    return 0;
}

/*
 * Check the first 16 bytes of critical functions for trampoline patterns.
 * Inline hooking frameworks (Frida, Substrate, etc.) overwrite the prologue
 * with a jump to the hook handler.
 */
__attribute__((annotate("fla"), annotate("sub")))
static int check_inline_hooks(void) {
    /* Function pointers to check. */
    typedef void (*fn_ptr_t)(void);
    const fn_ptr_t targets[] = {
        (fn_ptr_t)enko_native_detect_risk,
        (fn_ptr_t)enko_derive_payload_key,
        (fn_ptr_t)enko_gcm_decrypt,
    };
    static const int num_targets = sizeof(targets) / sizeof(targets[0]);

    for (int t = 0; t < num_targets; t++) {
        const uint8_t *code = (const uint8_t *)targets[t];

#if defined(__aarch64__)
        /* ARM64 trampoline patterns (4-byte instruction words):
         *   BR  X16 = 0xD61F0200
         *   BR  X17 = 0xD61F0220
         *   BLR X16 = 0xD63F0200
         *   BLR X17 = 0xD63F0220
         *   LDR X16/X17, [PC, #imm] = 0x58xxxxxx (top 8 bits = 0x58)
         *   B   imm26 = 0x14xxxxxx
         */
        for (int i = 0; i <= 12; i += 4) {
            uint32_t insn = *(const uint32_t *)(code + i);
            /* BR/BLR X16 or X17 */
            if (insn == 0xD61F0200 || insn == 0xD61F0220 ||
                insn == 0xD63F0200 || insn == 0xD63F0220) {
                return 1;
            }
            /* LDR Xn, [PC, #offset] where Xn is X16 or X17 */
            if ((insn & 0xFF000000) == 0x58000000) {
                uint32_t rt = insn & 0x1F;
                if (rt == 16 || rt == 17) return 1;
            }
            /* Unconditional branch B to a far address */
            if ((insn & 0xFC000000) == 0x14000000) {
                int32_t offset = (int32_t)((insn & 0x03FFFFFF) << 2);
                if (offset < 0) offset = -offset;
                if (offset > 4096) return 1;
            }
        }

#elif defined(__arm__)
        /* ARM32 trampoline patterns:
         *   LDR PC, [PC, #-4]  = 0xE51FF004
         *   BX  Rn              = 0xE12FFF1n
         */
        for (int i = 0; i <= 12; i += 4) {
            uint32_t insn = *(const uint32_t *)(code + i);
            if (insn == 0xE51FF004) return 1;
            if ((insn & 0xFFFFFFF0) == 0xE12FFF10) return 1;
        }

        /* Thumb mode: check if function address has bit 0 set */
        if ((uintptr_t)targets[t] & 1) {
            const uint8_t *thumb = code - 1; /* strip Thumb bit */
            for (int i = 0; i <= 12; i += 2) {
                uint16_t hw = *(const uint16_t *)(thumb + i);
                /* LDR.W PC, [PC, #imm] = DF F8 xx Fx */
                if (hw == 0xF8DF) {
                    uint16_t hw2 = *(const uint16_t *)(thumb + i + 2);
                    if ((hw2 & 0xF000) == 0xF000) return 1;
                }
            }
        }

#elif defined(__i386__) || defined(__x86_64__)
        /* x86/x64 trampoline patterns:
         *   JMP rel32   = 0xE9
         *   JMP [addr]  = 0xFF 0x25
         *   PUSH + RET  = 0x68 ... 0xC3
         */
        if (code[0] == 0xE9) return 1;
        if (code[0] == 0xFF && code[1] == 0x25) return 1;
        if (code[0] == 0x68 && code[5] == 0xC3) return 1;
        for (int i = 0; i < 8; i++) {
            if (code[i] == 0xE9) return 1;
            if (i + 1 < 16 && code[i] == 0xFF && code[i+1] == 0x25) return 1;
        }
#endif
    }
    if (check_code_guard_integrity()) {
        return 1;
    }
    if (check_mapped_lib_guard_integrity()) {
        return 1;
    }
    if (check_got_integrity()) {
        return 1;
    }
    return 0;
}

/* ---- Background watchdog thread ---- */
static volatile int g_watchdog_running = 0;

__attribute__((annotate("fla"), annotate("bcf")))
static void *watchdog_thread(void *arg) {
    (void)arg;
    while (g_watchdog_running) {
        if (check_tracer_pid()) {
            ad_enforce("tracer detected by watchdog");
        }
        if (check_tracer_pid_syscall()) {
            ad_enforce("tracer detected by syscall check");
        }
        if (check_wchan_ptrace()) {
            ad_enforce("ptrace_stop detected via wchan");
        }
        if (check_frida_maps()) {
            ad_enforce("frida detected by watchdog (maps)");
        }
        if (check_frida_threads()) {
            ad_enforce("frida detected by watchdog (threads)");
        }
        if (check_frida_memory_pattern()) {
            ad_enforce("frida detected by watchdog (memory pattern)");
        }
        if (check_suspicious_fds()) {
            ad_enforce("suspicious fd detected by watchdog");
        }
        if (check_frida_server_port()) {
            ad_enforce("frida server port detected by watchdog");
        }
        if (check_debugger_processes()) {
            ad_enforce("debugger process detected by watchdog");
        }
        if (check_suspicious_env()) {
            ad_enforce("suspicious env variable detected by watchdog");
        }
        if (check_inline_hooks()) {
            ad_enforce("inline hook detected by watchdog");
        }
        if (check_got_integrity()) {
            ad_enforce("GOT hook detected by watchdog");
        }
        sleep(2);
    }
    return NULL;
}

static void start_detached_thread(void *(*func)(void *)) {
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&tid, &attr, func, NULL);
    pthread_attr_destroy(&attr);
}

/* ---- Public API ---- */
__attribute__((annotate("fla")))
void enko_anti_debug_start(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        LOGW("ptrace(TRACEME) failed \xe2\x80\x94 debugger attached?");
    }

    init_code_guard_baseline();
    init_got_guard();

    /* Synchronous inline-hook check at JNI_OnLoad time — no race window. */
    if (check_inline_hooks()) {
        LOGW("inline hook detected at JNI_OnLoad");
        _exit(1);
    }
    if (check_got_integrity()) {
        LOGW("GOT hook detected at JNI_OnLoad");
        _exit(1);
    }
    if (check_suspicious_env()) {
        LOGW("suspicious env inject at JNI_OnLoad");
        _exit(1);
    }
    g_watchdog_running = 1;
    start_detached_thread(watchdog_thread);
    start_detached_thread(inotify_watcher_thread);
}

int enko_native_detect_risk(void) {
    int flags = 0;

    if (check_tracer_pid() || check_tracer_pid_syscall()) {
        flags |= 1;
    }

    if (check_wchan_ptrace()) {
        flags |= 1;
    }

    if (check_frida_maps() || check_frida_threads() ||
        check_frida_memory_pattern() || check_suspicious_fds() ||
        check_frida_server_port()) {
        flags |= 2;
    }

    /* Debugger processes or suspicious env (bit 1 — same as frida). */
    if (check_debugger_processes() || check_suspicious_env()) {
        flags |= 2;
    }

    /* Timing check: a trivial code path should complete in < 50ms. */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    volatile int dummy = 0;
    for (int i = 0; i < 100000; i++) dummy += i;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000 +
                      (t1.tv_nsec - t0.tv_nsec) / 1000000;
    if (elapsed_ms > 500) {
        flags |= 4;
    }

    /* Inline hook detection (bit 3). */
    if (check_inline_hooks()) {
        flags |= 8;
    }

    /* Root environment (bit 4). */
    if (check_root_indicators()) {
        flags |= 16;
    }

    /* Emulator environment (bit 5). */
    if (check_emulator_indicators()) {
        flags |= 32;
    }

    /* Hook-framework traces (bit 6). */
    if (check_hook_framework_maps()) {
        flags |= 64;
    }

    /* Anti-dump strong signal (bit 7). */
    int dump_flags = enko_detect_dump_tools();
    if (dump_flags & (1 | 2 | 4)) {
        flags |= 128;
    }

    /* System integrity anomaly (bit 8). */
    if (check_system_integrity_indicators()) {
        flags |= 256;
    }

    (void)dummy;
    return flags;
}

enum {
    PROFILE_BALANCED = 0,
    PROFILE_STRICT = 1,
    PROFILE_COMPAT = 2,
};

static int profile_mode_from_str(const char *profile) {
    if (!profile) return PROFILE_BALANCED;
    if (strcmp(profile, "strict") == 0) return PROFILE_STRICT;
    if (strcmp(profile, "compat") == 0) return PROFILE_COMPAT;
    return PROFILE_BALANCED;
}

static int is_high_confidence_reason(const char *reason) {
    if (!reason || !*reason) return 0;
    if (strcmp(reason, "debugger-attached") == 0) return 1;
    if (strcmp(reason, "tracer-detected") == 0) return 1;
    if (strcmp(reason, "native-tracer-detected") == 0) return 1;
    if (strcmp(reason, "hook-framework-detected") == 0) return 1;
    if (strcmp(reason, "native-inline-hook-detected") == 0) return 1;
    if (strcmp(reason, "dump-tool-detected") == 0) return 1;
    if (strstr(reason, "frida") != NULL) return 1;
    return 0;
}

static int weight_reason(const char *reason, int profile_mode) {
    const int strict = (profile_mode == PROFILE_STRICT);
    const int compat = (profile_mode == PROFILE_COMPAT);

    if (is_high_confidence_reason(reason)) {
        return strict ? 12 : (compat ? 8 : 10);
    }

    if (strncmp(reason, "capture-app-detected", 20) == 0) {
        return strict ? 8 : (compat ? 5 : 6);
    }
    if (strcmp(reason, "user-ca-detected") == 0) {
        return strict ? 6 : (compat ? 3 : 4);
    }
    if (strstr(reason, "proxy-detected") != NULL ||
        strcmp(reason, "vpn-detected") == 0 ||
        strcmp(reason, "vpn-interface-detected") == 0) {
        return strict ? 4 : (compat ? 1 : 2);
    }
    if (strcmp(reason, "root-environment") == 0) {
        return strict ? 6 : (compat ? 2 : 3);
    }
    if (strcmp(reason, "emulator-environment") == 0) {
        return strict ? 3 : (compat ? 0 : 1);
    }
    if (strcmp(reason, "native-timing-anomaly") == 0) {
        return strict ? 4 : (compat ? 1 : 2);
    }
    if (strcmp(reason, "dump-tool-detected") == 0) {
        return strict ? 10 : (compat ? 6 : 8);
    }
    if (strcmp(reason, "system-integrity-anomaly") == 0) {
        return strict ? 5 : (compat ? 1 : 2);
    }

    return strict ? 4 : (compat ? 1 : 2);
}

static int should_block_decision(
        int block_policy,
        int profile_mode,
        int score,
        int signal_count,
        int high_count) {
    if (!block_policy || signal_count == 0) {
        return 0;
    }
    if (profile_mode == PROFILE_STRICT) {
        return 1;
    }
    if (profile_mode == PROFILE_COMPAT) {
        if (high_count >= 2) {
            return 1;
        }
        return (high_count >= 1 && score >= 16) ? 1 : 0;
    }
    if (high_count >= 2) {
        return 1;
    }
    if (high_count >= 1 && score >= 10) {
        return 1;
    }
    return score >= 12 ? 1 : 0;
}

static void normalize_reason_token(const char *in, char *out, size_t out_len) {
    if (!out || out_len == 0) return;
    out[0] = '\0';
    if (!in) return;

    while (*in == ' ' || *in == '\t' || *in == '\r' || *in == '\n') {
        in++;
    }
    size_t len = strlen(in);
    while (len > 0) {
        char c = in[len - 1];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            len--;
            continue;
        }
        break;
    }
    if (len == 0) return;

    size_t n = (len < out_len - 1) ? len : (out_len - 1);
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)tolower((unsigned char)in[i]);
    }
    out[n] = '\0';
}

int enko_native_evaluate_risk(
        const char *risk_profile,
        int block_policy,
        const char *reasons_csv,
        int *out_score,
        int *out_signal_count,
        int *out_high_count,
        int *out_should_block) {
    if (!out_score || !out_signal_count || !out_high_count || !out_should_block) {
        return -1;
    }

    *out_score = 0;
    *out_signal_count = 0;
    *out_high_count = 0;
    *out_should_block = 0;

    if (!reasons_csv || !*reasons_csv) {
        return 0;
    }

    const int profile_mode = profile_mode_from_str(risk_profile);

    size_t csv_len = strlen(reasons_csv);
    char *copy = (char *)malloc(csv_len + 1);
    if (!copy) {
        return -1;
    }
    memcpy(copy, reasons_csv, csv_len + 1);

    /* Deduplicate by normalized reason text. */
    char seen[64][128];
    int seen_count = 0;

    char *saveptr = NULL;
    char *tok = strtok_r(copy, ",", &saveptr);
    while (tok) {
        char norm[128];
        normalize_reason_token(tok, norm, sizeof(norm));
        if (norm[0] != '\0') {
            int duplicate = 0;
            for (int i = 0; i < seen_count; i++) {
                if (strcmp(seen[i], norm) == 0) {
                    duplicate = 1;
                    break;
                }
            }
            if (!duplicate) {
                if (seen_count < (int)(sizeof(seen) / sizeof(seen[0]))) {
                    strncpy(seen[seen_count], norm, sizeof(seen[seen_count]) - 1);
                    seen[seen_count][sizeof(seen[seen_count]) - 1] = '\0';
                    seen_count++;
                }
                (*out_signal_count)++;
                *out_score += weight_reason(norm, profile_mode);
                if (is_high_confidence_reason(norm)) {
                    (*out_high_count)++;
                }
            }
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }

    *out_should_block = should_block_decision(
            block_policy,
            profile_mode,
            *out_score,
            *out_signal_count,
            *out_high_count);

    free(copy);
    return 0;
}

