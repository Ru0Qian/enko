#ifndef ENKO_ANTI_DUMP_H
#define ENKO_ANTI_DUMP_H

#include <stddef.h>
#include <stdint.h>

/**
 * Core anti-dump initialization.  Call once at startup.
 *
 *  1. prctl(PR_SET_DUMPABLE, 0)  — blocks /proc/self/mem read by
 *     non-root and prevents core dumps.
 *  2. Installs SIGCHLD watcher to detect fork-based dump attacks.
 *  3. Starts a background thread that monitors /proc for known
 *     dump-tool processes (dexdump, GameGuardian, dump_dex, etc.).
 */
void enko_anti_dump_init(void);

/**
 * Mark a memory region as MADV_DONTDUMP (excluded from core dumps).
 * The address is page-aligned internally.
 * Returns 0 on success, -1 on error.
 */
int enko_mark_no_dump(void *addr, size_t len);

/**
 * Protect a DEX memory region with mprotect(PROT_NONE).
 * This blocks /proc/self/mem reads by external processes (e.g. dump tools).
 * The region is page-aligned internally.
 * Returns 0 on success, -1 on error.
 */
int enko_protect_dex_region(void *addr, size_t len);

/**
 * Wipe a memory region with zeros.  Uses volatile writes to
 * prevent compiler optimisation, then calls madvise(MADV_DONTNEED)
 * to hint the kernel to reclaim the physical pages.
 *
 * Returns 0 on success, -1 on error.
 */
int enko_wipe_memory(void *addr, size_t len);

/**
 * Scan /proc for known memory-dump tool processes.
 * Returns bitmask:
 *   bit 0: dump tool detected
 *   bit 1: GameGuardian / memory editor detected
 *   bit 2: another process has our /proc/<pid>/maps or /proc/<pid>/mem open
 *   bit 3: current process has suspicious self maps/mem fd leak
 *   bit 4: coredump_filter is not hardened (non-zero)
 *   bit 5: weak heuristic process match (monitor only)
 */
int enko_detect_dump_tools(void);

#endif
