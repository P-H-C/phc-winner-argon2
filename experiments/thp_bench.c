/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 *
 * ---------------------------------------------------------------------------
 * Reproducible Transparent Huge Pages (THP) experiment for Argon2id.
 *
 * Compares the default allocation path (malloc/free) against a 2 MiB-aligned
 * allocator that also issues madvise(MADV_HUGEPAGE), using Argon2's
 * allocate_cbk/free_cbk callbacks. Both variants share the exact same harness,
 * the same fixed inputs and the same Argon2id v=19 parameters, and produce
 * byte-identical digests which are verified.
 *
 * The allocators are used through argon2_context callbacks only; the
 * cryptographic implementation in src/ is not modified in any way.
 * Secure memory wiping (FLAG_clear_internal_memory, which defaults to 1) is
 * left untouched and is never disabled. The harness additionally wipes its own
 * input/output buffers at exit.
 *
 * Allocation lifecycle and memory inspection:
 *   Argon2's free_cbk is the variant's real deallocator (free / thp free);
 *   no lifecycle is altered during the timed trials. Huge-page usage is NOT
 *   inferred from the timed hashes (glibc munmaps the 64 MiB mmap block on
 *   free(), so the process RSS/AnonHugePages drops to ~0 right after a hash).
 *   Instead, memory inspection is isolated OUTSIDE the timed region: after
 *   each timed trial, a memory_probe() allocates a block of the same size
 *   through the same allocator, touches every page, reads RSS/AnonHugePages
 *   from smaps, and frees it. The probe is never timed, so it cannot perturb
 *   the performance measurements and it leaves the allocation lifecycle of
 *   the timed hashes untouched. Actual huge-page usage is evidenced only by
 *   the probe's AnonHugePages reading, not by the madvise() return value.
 *
 * Energy (RAPL):
 *   Package energy is read from sysfs powercap. ALL top-level CPU package
 *   domains are detected (one per physical package, e.g. package-0 and
 *   package-1 on a dual-socket node) and their energy is summed. Nested
 *   domains (core/uncore/dram) and the platform domain (psys) are excluded by
 *   matching only domains whose name contains "package", so nothing is
 *   double-counted. Each domain's max_energy_range_uj is read and used as the
 *   actual hardware wraparound range for that domain. The counter is sampled
 *   on every hash inside the timed region and deltas are accumulated, so a
 *   wrap can never be missed and multiple wraps are handled correctly.
 *
 *   Idle baseline: a trimmed mean of several one-second idle samples is taken
 *   before the trials and subtracted (per domain) to estimate the energy that
 *   would have been consumed during each trial without Argon2. The corrected
 *   value is kept SIGNED: a negative corrected value is reported as-is (the
 *   process consumed less than the idle estimate), never clamped to zero.
 *
 *   Limitations / attribution: the powercap counters cover every core in the
 *   package, not just this process. On a shared node any concurrent workload
 *   inflates the readings, so the numbers are inherently uncertain and must
 *   not be attributed to Argon2. Even on an exclusively allocated node the
 *   idle-corrected package energy is only an ESTIMATE of the Argon2 share:
 *   it still includes kernel activity, idle leakage of other cores, and this
 *   harness's own non-hashing work. For this reason all energy values are
 *   reported as estimated; there is no flag that turns them into a direct
 *   per-process attribution. No root or system-wide settings are required;
 *   powercap sysfs is world-readable.
 * ---------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#ifdef __linux__
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/time.h>
#endif

#include "argon2.h"

#define DEFAULT_HASHES 1000
#define DEFAULT_TRIALS 3
#define DEFAULT_WARMUP 5
#define DEFAULT_MCOST 65536
#define DEFAULT_TCOST 3
#define DEFAULT_LANES 4
#define DEFAULT_OUTLEN 32
#define DEFAULT_PWDLEN 32
#define DEFAULT_SALTLEN 16

#define HUGE_PAGE_KB 2048
#define HUGE_PAGE_SIZE (HUGE_PAGE_KB * 1024)

#define RAPL_MAX_DOMAINS 8
#define RAPL_IDLE_SAMPLES 5

typedef enum { V_MALLOC, V_THP, V_BOTH } variant_t;

typedef struct {
    uint32_t hashes;
    uint32_t trials;
    uint32_t warmup;
    uint32_t m_cost;
    uint32_t t_cost;
    uint32_t lanes;
    uint32_t threads;
    uint32_t outlen;
    uint32_t pwdlen;
    uint32_t saltlen;
    variant_t variant;
    const char *csv_path;
    const char *per_hash_path;
    int quiet;
    int no_rapl;
} run_cfg;

typedef struct {
    const char *name;
    const char *order;
    uint32_t trial;
    double wall_sec;
    double cpu_sec;
    long probe_rss_kb;
    long probe_anon_hp_kb;
    long peak_rss_kb;
    int mem_ok;
    unsigned madvise_ok;
    unsigned madvise_fail;
    int rapl_available;
    const char *rapl_domains;
    uint64_t rapl_energy_uj;
    uint64_t rapl_idle_uj;
    int64_t rapl_corrected_uj;
    int energy_estimated;
    uint32_t hash_errors;
} trial_result;

typedef struct {
    const char *name;
    double wall_sec;
    double cpu_sec;
    uint64_t rapl_energy_uj;
    int64_t rapl_corrected_uj;
    long peak_rss_kb;
    uint32_t errors;
} variant_total;

typedef struct {
    int count;
    int available;
    char path[RAPL_MAX_DOMAINS][256];
    char name[RAPL_MAX_DOMAINS][128];
    uint64_t range[RAPL_MAX_DOMAINS];
    char domains_label[256];
} rapl_src;

typedef struct {
    uint64_t v[RAPL_MAX_DOMAINS];
} rapl_snap;

typedef struct {
    long rss_kb;
    long anon_hp_kb;
    int ok;
} probe_result;

static struct {
    unsigned ok;
    unsigned fail;
} g_madvise;

static double now_wall(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + 1e-9 * (double)ts.tv_nsec;
}

static double now_cpu(void) {
#if defined(CLOCK_PROCESS_CPUTIME_ID)
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (double)ts.tv_sec + 1e-9 * (double)ts.tv_nsec;
#else
    return now_wall();
#endif
}

static int malloc_allocate(uint8_t **mem, size_t bytes) {
    *mem = (uint8_t *)malloc(bytes);
    return (*mem != NULL) ? 0 : ARGON2_MEMORY_ALLOCATION_ERROR;
}

static void malloc_deallocate(uint8_t *mem, size_t bytes) {
    (void)bytes;
    free(mem);
}

static int thp_allocate(uint8_t **mem, size_t bytes) {
    void *p = NULL;
    if (posix_memalign(&p, HUGE_PAGE_SIZE, bytes) != 0 || p == NULL) {
        *mem = NULL;
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
#ifdef __linux__
    if (madvise(p, bytes, MADV_HUGEPAGE) == 0) {
        ++g_madvise.ok;
    } else {
        ++g_madvise.fail;
    }
#endif
    *mem = (uint8_t *)p;
    return ARGON2_OK;
}

static void thp_deallocate(uint8_t *mem, size_t bytes) {
    (void)bytes;
    free(mem);
}

/*
 * Reads a per-process memory accounting value from /proc/self/smaps_rollup
 * (falling back to /proc/self/smaps). Values are in kB and are summed, which
 * is exact for smaps_rollup (one line per key) and correct for smaps (all
 * mappings). Returns 1 if the measurement is available, 0 otherwise.
 */
static int parse_smaps_sum_kb(const char *key, long *out) {
#ifdef __linux__
    const char *paths[2] = {"/proc/self/smaps_rollup", "/proc/self/smaps"};
    size_t klen = strlen(key);
    int i;
    for (i = 0; i < 2; ++i) {
        FILE *f = fopen(paths[i], "r");
        char line[256];
        long sum = 0;
        int found = 0;
        if (f == NULL) {
            continue;
        }
        while (fgets(line, sizeof(line), f) != NULL) {
            if (strncmp(line, key, klen) == 0) {
                sum += atol(line + klen);
                found = 1;
            }
        }
        fclose(f);
        if (found) {
            *out = sum;
            return 1;
        }
    }
    return 0;
#else
    (void)key;
    (void)out;
    return 0;
#endif
}

static long peak_rss_kb(void) {
#ifdef __linux__
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        return (long)ru.ru_maxrss;
    }
#else
    (void)0;
#endif
    return -1;
}

static void read_thp_mode(char *buf, size_t buflen) {
#ifdef __linux__
    FILE *f = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "r");
    if (f == NULL) {
        snprintf(buf, buflen, "unavailable");
        return;
    }
    if (fgets(buf, (int)buflen, f) == NULL) {
        snprintf(buf, buflen, "unavailable");
    }
    fclose(f);
#else
    (void)buflen;
    snprintf(buf, buflen, "n/a (non-Linux)");
#endif
}

static uint64_t read_u64_file(const char *path, uint64_t fallback) {
    FILE *f = fopen(path, "r");
    unsigned long long v;
    if (f == NULL) {
        return fallback;
    }
    if (fscanf(f, "%llu", &v) != 1) {
        fclose(f);
        return fallback;
    }
    fclose(f);
    return (uint64_t)v;
}

/*
 * Detect ALL top-level CPU package domains under /sys/class/powercap.
 * Only domains whose name contains "package"/"pkg" are selected: nested
 * domains (core/uncore/dram) and the platform domain (psys) are excluded,
 * so nothing is double-counted. For each selected domain the actual hardware
 * wraparound range (max_energy_range_uj) is read.
 */
static int rapl_open(rapl_src *r) {
    r->count = 0;
    r->available = 0;
    r->domains_label[0] = '\0';
#ifdef __linux__
    DIR *dir = opendir("/sys/class/powercap");
    struct dirent *e;
    if (dir == NULL) {
        return 0;
    }
    while ((e = readdir(dir)) != NULL && r->count < RAPL_MAX_DOMAINS) {
        char dpath[256], npath[288], epath[288], rpath[288], nm[128];
        FILE *f;
        if (e->d_name[0] == '.') {
            continue;
        }
        snprintf(dpath, sizeof(dpath), "/sys/class/powercap/%s", e->d_name);
        snprintf(epath, sizeof(epath), "%s/energy_uj", dpath);
        if (access(epath, R_OK) != 0) {
            continue;
        }
        snprintf(npath, sizeof(npath), "%s/name", dpath);
        f = fopen(npath, "r");
        nm[0] = '\0';
        if (f != NULL) {
            if (fgets(nm, sizeof(nm), f) == NULL) {
                nm[0] = '\0';
            }
            fclose(f);
            nm[strcspn(nm, "\n")] = '\0';
        }
        if (strstr(nm, "package") == NULL && strstr(nm, "pkg") == NULL) {
            continue;
        }
        snprintf(r->path[r->count], 256, "%s", epath);
        snprintf(r->name[r->count], 128, "%s",
                 nm[0] != '\0' ? nm : e->d_name);
        snprintf(rpath, sizeof(rpath), "%s/max_energy_range_uj", dpath);
        r->range[r->count] = read_u64_file(rpath, UINT64_MAX);
        ++r->count;
    }
    closedir(dir);
    if (r->count > 0) {
        int i;
        r->available = 1;
        snprintf(r->domains_label, sizeof(r->domains_label), "%s",
                 r->name[0]);
        for (i = 1; i < r->count; ++i) {
            snprintf(r->domains_label + strlen(r->domains_label),
                     sizeof(r->domains_label) - strlen(r->domains_label),
                     "+%s", r->name[i]);
        }
    }
#endif
    return r->available;
}

static int rapl_snap_read(const rapl_src *r, rapl_snap *s) {
    int i;
    if (r->available == 0) {
        return 0;
    }
    for (i = 0; i < r->count; ++i) {
        s->v[i] = read_u64_file(r->path[i], UINT64_MAX);
        if (s->v[i] == UINT64_MAX) {
            return 0;
        }
    }
    return 1;
}

/*
 * Difference of a wrapping counter using the domain's actual hardware range.
 * A single wrap is handled exactly; because sampling happens on every hash,
 * the per-sample delta is always far below the range, so no wrap is missed.
 */
static uint64_t rapl_delta_val(uint64_t after, uint64_t before,
                               uint64_t range) {
    if (after >= before) {
        return after - before;
    }
    return (range - before) + after;
}

static uint64_t rapl_total_energy(const rapl_src *r, const uint64_t acc[]) {
    uint64_t total = 0;
    int i;
    for (i = 0; i < r->count; ++i) {
        total += acc[i];
    }
    return total;
}

/*
 * Idle package energy rate (uJ/s) per domain, as a trimmed mean of several
 * one-second samples. Returns 0 on success.
 */
static int rapl_idle_rate(const rapl_src *r, double rate[RAPL_MAX_DOMAINS]) {
    uint64_t samples[RAPL_IDLE_SAMPLES][RAPL_MAX_DOMAINS];
    int k, d;
    if (r->available == 0) {
        return 1;
    }
    for (k = 0; k < RAPL_IDLE_SAMPLES; ++k) {
        rapl_snap a, b;
        struct timespec ts;
        ts.tv_sec = 1;
        ts.tv_nsec = 0;
        if (!rapl_snap_read(r, &b)) {
            return 1;
        }
        nanosleep(&ts, NULL);
        if (!rapl_snap_read(r, &a)) {
            return 1;
        }
        for (d = 0; d < r->count; ++d) {
            samples[k][d] = rapl_delta_val(a.v[d], b.v[d], r->range[d]);
        }
    }
    for (d = 0; d < r->count; ++d) {
        uint64_t tmp[RAPL_IDLE_SAMPLES];
        uint64_t sum = 0;
        int i, j;
        for (i = 0; i < RAPL_IDLE_SAMPLES; ++i) {
            tmp[i] = samples[i][d];
        }
        for (i = 0; i < RAPL_IDLE_SAMPLES - 1; ++i) {
            for (j = i + 1; j < RAPL_IDLE_SAMPLES; ++j) {
                if (tmp[j] < tmp[i]) {
                    uint64_t t = tmp[i];
                    tmp[i] = tmp[j];
                    tmp[j] = t;
                }
            }
        }
        for (i = 1; i < RAPL_IDLE_SAMPLES - 1; ++i) {
            sum += tmp[i];
        }
        rate[d] = (double)sum / (double)(RAPL_IDLE_SAMPLES - 2);
    }
    return 0;
}

/*
 * Isolated memory inspection (never timed): allocate through the variant's
 * allocator, touch every page, read RSS/AnonHugePages, then free.
 */
static probe_result memory_probe(allocate_fptr alloc, deallocate_fptr dealloc,
                                 size_t bytes) {
    probe_result p;
    uint8_t *m = NULL;
    p.rss_kb = -1;
    p.anon_hp_kb = -1;
    p.ok = 0;
    if (alloc(&m, bytes) != 0 || m == NULL) {
        return p;
    }
    memset(m, 0x5a, bytes);
    parse_smaps_sum_kb("Rss:", &p.rss_kb);
    p.ok = parse_smaps_sum_kb("AnonHugePages:", &p.anon_hp_kb);
    dealloc(m, bytes);
    return p;
}

static const char *variant_name(variant_t v) {
    switch (v) {
    case V_MALLOC:
        return "malloc";
    case V_THP:
        return "thp";
    default:
        return "both";
    }
}

static void fill_pattern(uint8_t *buf, size_t len, uint32_t seed) {
    size_t i;
    for (i = 0; i < len; ++i) {
        buf[i] = (uint8_t)((i * (seed % 251u) + seed) & 0xffu);
    }
}

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    size_t i;
    printf("%s", label);
    for (i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static void usage(const char *prog) {
    printf(
        "Usage: %s [options]\n"
        "Reproducible Transparent Huge Pages benchmark for Argon2id.\n"
        "\n"
        "Options:\n"
        "  -h, --help             show this help\n"
        "  -n, --hashes N         hashes per trial (default %u)\n"
        "  -t, --trials T         number of trials (default %u)\n"
        "  -w, --warmup W         warm-up hashes before timing (default %u)\n"
        "  -v, --variant V        malloc | thp | both (default both)\n"
        "  -c, --csv FILE         write CSV to FILE, '-' for stdout\n"
        "                         (default: thp_bench_results.csv)\n"
        "  -p, --per-hash FILE    write per-hash CSV rows to FILE\n"
        "      --m-cost KiB       memory cost in KiB (default %u)\n"
        "      --t-cost N         time cost (default %u)\n"
        "      --lanes N          parallelism/lanes (default %u)\n"
        "      --outlen N         digest length in bytes (default %u)\n"
        "      --pwdlen N         password length in bytes (default %u)\n"
        "      --saltlen N        salt length in bytes (default %u)\n"
        "      --no-rapl          disable RAPL energy sampling\n"
        "  -q, --quiet            suppress per-trial progress output\n",
        prog, DEFAULT_HASHES, DEFAULT_TRIALS, DEFAULT_WARMUP, DEFAULT_MCOST,
        DEFAULT_TCOST, DEFAULT_LANES, DEFAULT_OUTLEN, DEFAULT_PWDLEN,
        DEFAULT_SALTLEN);
}

static int parse_args(int argc, char **argv, run_cfg *cfg) {
    enum {
        OPT_MCOST = 1000,
        OPT_TCOST,
        OPT_LANES,
        OPT_OUTLEN,
        OPT_PWDLEN,
        OPT_SALTLEN,
        OPT_NO_RAPL
    };
    static const struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"hashes", required_argument, NULL, 'n'},
        {"trials", required_argument, NULL, 't'},
        {"warmup", required_argument, NULL, 'w'},
        {"variant", required_argument, NULL, 'v'},
        {"csv", required_argument, NULL, 'c'},
        {"per-hash", required_argument, NULL, 'p'},
        {"m-cost", required_argument, NULL, OPT_MCOST},
        {"t-cost", required_argument, NULL, OPT_TCOST},
        {"lanes", required_argument, NULL, OPT_LANES},
        {"outlen", required_argument, NULL, OPT_OUTLEN},
        {"pwdlen", required_argument, NULL, OPT_PWDLEN},
        {"saltlen", required_argument, NULL, OPT_SALTLEN},
        {"no-rapl", no_argument, NULL, OPT_NO_RAPL},
        {"quiet", no_argument, NULL, 'q'},
        {NULL, 0, NULL, 0}};
    int opt;
    char *end;
    long value;

    memset(cfg, 0, sizeof(*cfg));
    cfg->hashes = DEFAULT_HASHES;
    cfg->trials = DEFAULT_TRIALS;
    cfg->warmup = DEFAULT_WARMUP;
    cfg->m_cost = DEFAULT_MCOST;
    cfg->t_cost = DEFAULT_TCOST;
    cfg->lanes = DEFAULT_LANES;
    cfg->threads = DEFAULT_LANES;
    cfg->outlen = DEFAULT_OUTLEN;
    cfg->pwdlen = DEFAULT_PWDLEN;
    cfg->saltlen = DEFAULT_SALTLEN;
    cfg->variant = V_BOTH;
    cfg->csv_path = "thp_bench_results.csv";

    while ((opt = getopt_long(argc, argv, "hn:t:w:v:c:p:q", longopts, NULL)) !=
           -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            exit(0);
        case 'q':
            cfg->quiet = 1;
            break;
        case OPT_NO_RAPL:
            cfg->no_rapl = 1;
            break;
        case 'n':
        case 't':
        case 'w':
            value = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0') {
                fprintf(stderr, "invalid numeric value: %s\n", optarg);
                return 1;
            }
            if (opt == 'n') {
                cfg->hashes = (uint32_t)value;
            } else if (opt == 't') {
                cfg->trials = (uint32_t)value;
            } else {
                cfg->warmup = (uint32_t)value;
            }
            break;
        case 'c':
            cfg->csv_path = optarg;
            break;
        case 'p':
            cfg->per_hash_path = optarg;
            break;
        case 'v':
            if (strcmp(optarg, "malloc") == 0) {
                cfg->variant = V_MALLOC;
            } else if (strcmp(optarg, "thp") == 0) {
                cfg->variant = V_THP;
            } else if (strcmp(optarg, "both") == 0) {
                cfg->variant = V_BOTH;
            } else {
                fprintf(stderr, "unknown variant: %s\n", optarg);
                return 1;
            }
            break;
        case OPT_MCOST:
        case OPT_TCOST:
        case OPT_LANES:
        case OPT_OUTLEN:
        case OPT_PWDLEN:
        case OPT_SALTLEN:
            value = strtol(optarg, &end, 10);
            if (end == optarg || *end != '\0') {
                fprintf(stderr, "invalid numeric value: %s\n", optarg);
                return 1;
            }
            switch (opt) {
            case OPT_MCOST:
                cfg->m_cost = (uint32_t)value;
                break;
            case OPT_TCOST:
                cfg->t_cost = (uint32_t)value;
                break;
            case OPT_LANES:
                cfg->lanes = (uint32_t)value;
                cfg->threads = (uint32_t)value;
                break;
            case OPT_OUTLEN:
                cfg->outlen = (uint32_t)value;
                break;
            case OPT_PWDLEN:
                cfg->pwdlen = (uint32_t)value;
                break;
            case OPT_SALTLEN:
                cfg->saltlen = (uint32_t)value;
                break;
            default:
                break;
            }
            break;
        default:
            usage(argv[0]);
            return 1;
        }
    }
    return 0;
}

static void ctx_init(argon2_context *ctx, const run_cfg *cfg,
                     const uint8_t *pwd, const uint8_t *salt, uint8_t *out,
                     allocate_fptr alloc, deallocate_fptr dealloc) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->out = out;
    ctx->outlen = cfg->outlen;
    ctx->pwd = (uint8_t *)pwd;
    ctx->pwdlen = cfg->pwdlen;
    ctx->salt = (uint8_t *)salt;
    ctx->saltlen = cfg->saltlen;
    ctx->secret = NULL;
    ctx->secretlen = 0;
    ctx->ad = NULL;
    ctx->adlen = 0;
    ctx->t_cost = cfg->t_cost;
    ctx->m_cost = cfg->m_cost;
    ctx->lanes = cfg->lanes;
    ctx->threads = cfg->threads;
    ctx->version = ARGON2_VERSION_13;
    ctx->allocate_cbk = alloc;
    ctx->free_cbk = dealloc;
    ctx->flags = ARGON2_DEFAULT_FLAGS;
}

static uint32_t warmup_variant(const run_cfg *cfg, const char *name,
                               allocate_fptr alloc, deallocate_fptr dealloc,
                               const uint8_t *pwd, const uint8_t *salt,
                               uint8_t *out) {
    argon2_context ctx;
    uint32_t i;
    uint32_t errors = 0;

    g_madvise.ok = 0;
    g_madvise.fail = 0;
    ctx_init(&ctx, cfg, pwd, salt, out, alloc, dealloc);

    for (i = 0; i < cfg->warmup; ++i) {
        if (argon2id_ctx(&ctx) != ARGON2_OK) {
            fprintf(stderr, "%s: warm-up hash %u failed\n", name, i);
            ++errors;
        }
    }
    return errors;
}

/*
 * Runs one trial of one variant. Returns the number of Argon2 hash errors
 * (0 on success). Times and energy are per-trial. RAPL is sampled on every
 * hash so no counter wrap can be missed; the idle estimate (per-domain rate
 * x trial wall time) is subtracted and the corrected value is kept signed.
 * Memory inspection happens via memory_probe() strictly AFTER the timed
 * region and does not alter the allocation lifecycle of the timed hashes.
 */
static uint32_t run_trial(const run_cfg *cfg, const char *name,
                          const char *order, uint32_t trial,
                          allocate_fptr alloc, deallocate_fptr dealloc,
                          const uint8_t *pwd, const uint8_t *salt,
                          uint8_t *out, const rapl_src *rapl,
                          const double idle_rate[RAPL_MAX_DOMAINS],
                          FILE *csv, FILE *per_hash, trial_result *tr) {
    argon2_context ctx;
    uint32_t i;
    int d;
    double wall0, wall1, cpu0, cpu1;
    uint64_t acc[RAPL_MAX_DOMAINS];
    uint64_t idle_total = 0;
    rapl_snap prev, cur;
    int rapl_on = rapl->available;

    memset(tr, 0, sizeof(*tr));
    tr->name = name;
    tr->order = order;
    tr->trial = trial;
    tr->rapl_domains = rapl->domains_label;
    tr->energy_estimated = 1;

    for (d = 0; d < RAPL_MAX_DOMAINS; ++d) {
        acc[d] = 0;
    }

    g_madvise.ok = 0;
    g_madvise.fail = 0;
    ctx_init(&ctx, cfg, pwd, salt, out, alloc, dealloc);

    if (rapl_on && !rapl_snap_read(rapl, &prev)) {
        rapl_on = 0;
    }

    wall0 = now_wall();
    cpu0 = now_cpu();
    for (i = 0; i < cfg->hashes; ++i) {
        double h0, h1;
        int rch;
        h0 = now_wall();
        rch = argon2id_ctx(&ctx);
        h1 = now_wall();
        if (rch != ARGON2_OK) {
            fprintf(stderr, "%s: hash %u failed in trial %u (error %d)\n",
                    name, i, trial, rch);
            ++tr->hash_errors;
        }
        if (per_hash != NULL) {
            fprintf(per_hash, "%s,%s,%u,%u,%.6f,%d\n", name, order, trial, i,
                    h1 - h0, rch == ARGON2_OK ? 0 : 1);
        }
        if (rapl_on && rapl_snap_read(rapl, &cur)) {
            for (d = 0; d < rapl->count; ++d) {
                acc[d] += rapl_delta_val(cur.v[d], prev.v[d], rapl->range[d]);
            }
            prev = cur;
        } else if (rapl_on) {
            rapl_on = 0;
        }
    }
    wall1 = now_wall();
    cpu1 = now_cpu();

    tr->wall_sec = wall1 - wall0;
    tr->cpu_sec = cpu1 - cpu0;

    tr->rapl_available = rapl_on;
    if (rapl_on) {
        uint64_t measured = rapl_total_energy(rapl, acc);
        for (d = 0; d < rapl->count; ++d) {
            idle_total += (uint64_t)(idle_rate[d] * tr->wall_sec);
        }
        tr->rapl_energy_uj = measured;
        tr->rapl_idle_uj = idle_total;
        tr->rapl_corrected_uj =
            (int64_t)measured - (int64_t)idle_total;
    }

    tr->madvise_ok = g_madvise.ok;
    tr->madvise_fail = g_madvise.fail;

    /* Memory inspection outside the timed region (never timed). */
    {
        probe_result pr = memory_probe(alloc, dealloc,
                                       (size_t)cfg->m_cost * 1024);
        tr->probe_rss_kb = pr.rss_kb;
        tr->probe_anon_hp_kb = pr.anon_hp_kb;
        tr->mem_ok = pr.ok;
    }
    tr->peak_rss_kb = peak_rss_kb();

    if (csv != NULL) {
        fprintf(csv,
                "%s,%s,%u,%u,%u,%.6f,%.6f,%.6f,%ld,%ld,%ld,%u,%u,%s,"
                "%llu,%llu,%lld,%d\n",
                name, order, trial, cfg->hashes, cfg->warmup, tr->wall_sec,
                tr->cpu_sec, (tr->wall_sec * 1000.0) / cfg->hashes,
                tr->probe_rss_kb, tr->probe_anon_hp_kb, tr->peak_rss_kb,
                tr->madvise_ok, tr->madvise_fail,
                tr->rapl_available ? tr->rapl_domains : "unsupported",
                (unsigned long long)tr->rapl_energy_uj,
                (unsigned long long)tr->rapl_idle_uj,
                (long long)tr->rapl_corrected_uj, tr->energy_estimated);
        fflush(csv);
    }

    if (!cfg->quiet) {
        if (tr->mem_ok) {
            printf("%-6s trial %u (%s): %u hashes in %.3f s "
                   "(%.3f ms/hash), probe RSS %ld kB, probe AnonHugePages "
                   "%ld kB, RAPL %s %llu uJ (idle-corrected %+lld uJ, "
                   "estimated)\n",
                   name, trial, order, cfg->hashes, tr->wall_sec,
                   (tr->wall_sec * 1000.0) / cfg->hashes, tr->probe_rss_kb,
                   tr->probe_anon_hp_kb,
                   tr->rapl_available ? tr->rapl_domains : "unsupported",
                   (unsigned long long)tr->rapl_energy_uj,
                   (long long)tr->rapl_corrected_uj);
        } else {
            printf("%-6s trial %u (%s): %u hashes in %.3f s "
                   "(%.3f ms/hash), AnonHugePages unsupported "
                   "(no smaps_rollup/smaps), RAPL %s %llu uJ "
                   "(idle-corrected %+lld uJ, estimated)\n",
                   name, trial, order, cfg->hashes, tr->wall_sec,
                   (tr->wall_sec * 1000.0) / cfg->hashes,
                   tr->rapl_available ? tr->rapl_domains : "unsupported",
                   (unsigned long long)tr->rapl_energy_uj,
                   (long long)tr->rapl_corrected_uj);
        }
    }

    return tr->hash_errors;
}

static void add_total(variant_total *t, const trial_result *tr) {
    t->wall_sec += tr->wall_sec;
    t->cpu_sec += tr->cpu_sec;
    t->rapl_energy_uj += tr->rapl_energy_uj;
    t->rapl_corrected_uj += tr->rapl_corrected_uj;
    t->errors += tr->hash_errors;
}

int main(int argc, char **argv) {
    run_cfg cfg;
    uint8_t *pwd = NULL;
    uint8_t *salt = NULL;
    uint8_t *out_malloc = NULL;
    uint8_t *out_thp = NULL;
    variant_total tm, tt;
    FILE *csv = NULL;
    FILE *per_hash = NULL;
    int rc = 0;
    uint32_t trial;
    uint32_t total_errors = 0;
    char thp_mode[128];
    rapl_src rapl;
    double idle_rate[RAPL_MAX_DOMAINS];
    long baseline_anon = -1;
    int mem_ok;

    memset(&tm, 0, sizeof(tm));
    memset(&tt, 0, sizeof(tt));
    tm.name = "malloc";
    tt.name = "thp";
    memset(idle_rate, 0, sizeof(idle_rate));

    if (parse_args(argc, argv, &cfg) != 0) {
        return 1;
    }

    pwd = (uint8_t *)malloc(cfg.pwdlen ? cfg.pwdlen : 1);
    salt = (uint8_t *)malloc(cfg.saltlen ? cfg.saltlen : 1);
    out_malloc = (uint8_t *)malloc(cfg.outlen ? cfg.outlen : 1);
    out_thp = (uint8_t *)malloc(cfg.outlen ? cfg.outlen : 1);
    if (pwd == NULL || salt == NULL || out_malloc == NULL || out_thp == NULL) {
        fprintf(stderr, "out of memory for inputs\n");
        rc = 1;
        goto done;
    }

    fill_pattern(pwd, cfg.pwdlen, 0x11u);
    fill_pattern(salt, cfg.saltlen, 0x22u);
    memset(out_malloc, 0, cfg.outlen);
    memset(out_thp, 0, cfg.outlen);

    read_thp_mode(thp_mode, sizeof(thp_mode));
    mem_ok = parse_smaps_sum_kb("AnonHugePages:", &baseline_anon);

    if (cfg.no_rapl) {
        memset(&rapl, 0, sizeof(rapl));
    } else {
        rapl_open(&rapl);
    }
    if (rapl.available) {
        int i;
        double idle_total = 0.0;
        if (rapl_idle_rate(&rapl, idle_rate) != 0) {
            fprintf(stderr, "RAPL idle sampling failed; disabling RAPL\n");
            rapl.available = 0;
        } else {
            for (i = 0; i < rapl.count; ++i) {
                idle_total += idle_rate[i];
            }
            printf("RAPL package domains: %s\n", rapl.domains_label);
            for (i = 0; i < rapl.count; ++i) {
                printf("  %s: wrap range %llu uJ, idle rate %.0f uJ/s "
                       "(trimmed mean of %d x 1 s samples)\n",
                       rapl.name[i],
                       (unsigned long long)rapl.range[i], idle_rate[i],
                       RAPL_IDLE_SAMPLES);
            }
            printf("Total idle package energy rate: %.0f uJ/s\n", idle_total);
            printf("WARNING: powercap counters cover every core in each "
                   "package. On a shared node, concurrent jobs inflate the "
                   "readings. All energy values are ESTIMATES and are not "
                   "attributable to Argon2, even on an exclusive node (they "
                   "still include kernel activity, idle leakage of other "
                   "cores, and this harness's own non-hashing work).\n");
        }
    } else {
        printf("RAPL: unsupported or disabled (no package energy_uj found). "
               "No energy measurements will be recorded.\n");
    }

    printf("Argon2id v=19, t=%u, m=%u KiB, p=%u, outlen=%u\n", cfg.t_cost,
           cfg.m_cost, cfg.lanes, cfg.outlen);
    printf("Variant: %s\n", variant_name(cfg.variant));
    printf("hashes/trial=%u trials=%u warmup=%u\n", cfg.hashes, cfg.trials,
           cfg.warmup);
    printf("THP mode (sysfs): %s", thp_mode);
    if (thp_mode[strlen(thp_mode) - 1] != '\n') {
        printf("\n");
    }
    if (mem_ok) {
        printf("Baseline AnonHugePages before hashing: %ld kB\n", baseline_anon);
    } else {
        printf("Baseline AnonHugePages: unsupported "
               "(no /proc/self/smaps_rollup or smaps)\n");
    }
    printf("Working set: %u KiB aligned to %d KiB for THP variant\n",
           cfg.m_cost, HUGE_PAGE_KB);

    if (cfg.csv_path != NULL) {
        if (strcmp(cfg.csv_path, "-") == 0) {
            csv = stdout;
        } else {
            csv = fopen(cfg.csv_path, "w");
            if (csv == NULL) {
                fprintf(stderr, "cannot open CSV file: %s\n", cfg.csv_path);
                rc = 1;
                goto done;
            }
        }
        fprintf(csv,
                "variant,order,trial,hashes,warmup,t_wall_s,t_cpu_s,"
                "per_hash_ms,probe_rss_kb,probe_anon_hugepages_kb,"
                "peak_rss_kb,madvise_ok,madvise_fail,rapl_domains,"
                "rapl_energy_uj,rapl_idle_uj,rapl_corrected_uj,"
                "energy_estimated\n");
        fflush(csv);
    }

    if (cfg.per_hash_path != NULL) {
        per_hash = fopen(cfg.per_hash_path, "w");
        if (per_hash == NULL) {
            fprintf(stderr, "cannot open per-hash file: %s\n",
                    cfg.per_hash_path);
            rc = 1;
            goto done;
        }
        fprintf(per_hash, "variant,order,trial,hash,wall_s,rc\n");
        fflush(per_hash);
    }

    /* Warm each active variant once (unmeasured). */
    if (cfg.variant == V_MALLOC || cfg.variant == V_BOTH) {
        total_errors += warmup_variant(&cfg, "malloc", malloc_allocate,
                                       malloc_deallocate, pwd, salt,
                                       out_malloc);
    }
    if (cfg.variant == V_THP || cfg.variant == V_BOTH) {
        total_errors += warmup_variant(&cfg, "thp", thp_allocate,
                                       thp_deallocate, pwd, salt, out_thp);
    }

    /*
     * Interleaved, counterbalanced trials: even trials run malloc-then-thp,
     * odd trials run thp-then-malloc, so any time drift affects both
     * variants equally and neither always runs first.
     */
    for (trial = 0; trial < cfg.trials; ++trial) {
        trial_result tr;
        if (cfg.variant == V_MALLOC) {
            total_errors +=
                run_trial(&cfg, "malloc", "single", trial, malloc_allocate,
                          malloc_deallocate, pwd, salt, out_malloc, &rapl,
                          idle_rate, csv, per_hash, &tr);
            add_total(&tm, &tr);
        } else if (cfg.variant == V_THP) {
            total_errors +=
                run_trial(&cfg, "thp", "single", trial, thp_allocate,
                          thp_deallocate, pwd, salt, out_thp, &rapl, idle_rate,
                          csv, per_hash, &tr);
            add_total(&tt, &tr);
        } else {
            if (trial % 2 == 0) {
                total_errors += run_trial(&cfg, "malloc", "malloc+thp", trial,
                                          malloc_allocate, malloc_deallocate,
                                          pwd, salt, out_malloc, &rapl,
                                          idle_rate, csv, per_hash, &tr);
                add_total(&tm, &tr);
                total_errors += run_trial(&cfg, "thp", "malloc+thp", trial,
                                          thp_allocate, thp_deallocate, pwd,
                                          salt, out_thp, &rapl, idle_rate, csv,
                                          per_hash, &tr);
                add_total(&tt, &tr);
            } else {
                total_errors += run_trial(&cfg, "thp", "thp+malloc", trial,
                                          thp_allocate, thp_deallocate, pwd,
                                          salt, out_thp, &rapl, idle_rate, csv,
                                          per_hash, &tr);
                add_total(&tt, &tr);
                total_errors += run_trial(&cfg, "malloc", "thp+malloc", trial,
                                          malloc_allocate, malloc_deallocate,
                                          pwd, salt, out_malloc, &rapl,
                                          idle_rate, csv, per_hash, &tr);
                add_total(&tm, &tr);
            }
        }
    }

    if (total_errors > 0) {
        fprintf(stderr, "%u Argon2 hashing error(s) occurred; see stderr "
                "and per-hash CSV (rc column)\n", total_errors);
        rc = 1;
    }

    if (cfg.variant == V_BOTH) {
        if (memcmp(out_malloc, out_thp, cfg.outlen) != 0) {
            fprintf(stderr,
                    "FATAL: outputs differ between malloc and thp variants\n");
            rc = 1;
        } else {
            printf("Output verification: identical across variants\n");
        }
    }

    printf("\nSummary (raw totals across %u trial(s); no claim of "
           "improvement is implied)\n", cfg.trials);
    printf("=======\n");
    if (cfg.variant == V_MALLOC || cfg.variant == V_BOTH) {
        printf("%-6s total %u hashes: %.3f s wall, %.3f s cpu, "
               "%.3f ms/hash",
               "malloc", cfg.hashes * cfg.trials, tm.wall_sec, tm.cpu_sec,
               (tm.wall_sec * 1000.0) / (cfg.hashes * cfg.trials));
        if (rapl.available) {
            printf(", RAPL %llu uJ (idle-corrected %+lld uJ, estimated)",
                   (unsigned long long)tm.rapl_energy_uj,
                   (long long)tm.rapl_corrected_uj);
        }
        printf("\n");
    }
    if (cfg.variant == V_THP || cfg.variant == V_BOTH) {
        printf("%-6s total %u hashes: %.3f s wall, %.3f s cpu, "
               "%.3f ms/hash",
               "thp", cfg.hashes * cfg.trials, tt.wall_sec, tt.cpu_sec,
               (tt.wall_sec * 1000.0) / (cfg.hashes * cfg.trials));
        if (rapl.available) {
            printf(", RAPL %llu uJ (idle-corrected %+lld uJ, estimated)",
                   (unsigned long long)tt.rapl_energy_uj,
                   (long long)tt.rapl_corrected_uj);
        }
        printf("\n");
    }
    printf("Note: peak_rss_kb in CSV is the process-lifetime maximum, "
           "not a per-variant measurement.\n");
    if (cfg.variant == V_MALLOC || cfg.variant == V_BOTH) {
        print_hex("malloc digest: ", out_malloc, cfg.outlen);
    }
    if (cfg.variant == V_THP || cfg.variant == V_BOTH) {
        print_hex("thp digest:    ", out_thp, cfg.outlen);
    }

done:
    if (csv != NULL && csv != stdout) {
        fclose(csv);
    }
    if (per_hash != NULL) {
        fclose(per_hash);
    }
    if (pwd != NULL) {
        memset(pwd, 0, cfg.pwdlen);
        free(pwd);
    }
    if (salt != NULL) {
        memset(salt, 0, cfg.saltlen);
        free(salt);
    }
    if (out_malloc != NULL) {
        memset(out_malloc, 0, cfg.outlen);
        free(out_malloc);
    }
    if (out_thp != NULL) {
        memset(out_thp, 0, cfg.outlen);
        free(out_thp);
    }
    return rc;
}
