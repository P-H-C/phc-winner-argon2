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
 * Deterministic digest checker for the persistent-workers experiment.
 *
 * Hashes a fixed, reproducible set of parameter combinations (types, versions,
 * memory/time costs, lane counts, secrets, associated data) with the exact
 * same sources that `make test` validates, and prints one line per case.
 * The baseline binary and the binary compiled with
 * -DARGON2_EXPERIMENT_PERSISTENT_WORKERS must produce byte-identical output;
 * the Slurm experiment diffs the two outputs and fails the job otherwise.
 *
 * The p=4, t=3, m=65536 KiB Argon2id v19 case (the production workload) is
 * included, as are p=1 (single-threaded), p=2, p=8, a lanes != threads case
 * that exercises the fallback to the original scheduler, and Argon2i/Argon2d.
 * Secure memory wiping (FLAG_clear_internal_memory, default 1) is untouched.
 * ---------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "argon2.h"

#define MAX_OUT 64

typedef struct {
    uint32_t t_cost;
    uint32_t m_cost;
    uint32_t lanes;
    uint32_t threads;
    uint32_t version;
    uint32_t outlen;
    argon2_type type;
    const char *label;
    const uint8_t *pwd;
    size_t pwdlen;
    const uint8_t *salt;
    size_t saltlen;
    const uint8_t *secret;
    size_t secretlen;
    const uint8_t *ad;
    size_t adlen;
} check_case;

static const uint8_t pwd_w[] = "workload password 0123456789abcdef"; /* 32 B */
static const uint8_t salt16[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                                 0xdd, 0xee, 0xff, 0x00};
static const uint8_t pwd_long[] = "a very long password that is considerably "
                                  "longer than a single cache line on modern "
                                  "CPUs and exercises a different password "
                                  "length path in the pre-hashing";
static const uint8_t salt8[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
static const uint8_t secret12[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
static const uint8_t ad12[] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                               0xba, 0xbe, 0x00, 0x11, 0x22, 0x33};

int main(void) {
    check_case cases[] = {
        /* 0: production workload (Argon2id v19, t=3, m=65536 KiB, p=4) */
        {3, 65536, 4, 4, ARGON2_VERSION_NUMBER, 32, Argon2_id,
         "workload_id_p4", pwd_w, sizeof(pwd_w) - 1, salt16, sizeof(salt16),
         NULL, 0, NULL, 0},
        /* 1: workload with secret and associated data */
        {3, 65536, 4, 4, ARGON2_VERSION_NUMBER, 32, Argon2_id,
         "workload_id_p4_secret_ad", pwd_w, sizeof(pwd_w) - 1,
         salt16, sizeof(salt16), secret12, sizeof(secret12), ad12,
         sizeof(ad12)},
        /* 2: version 16 (overwrite, not XOR, across passes) */
        {3, 65536, 4, 4, ARGON2_VERSION_10, 32, Argon2_id,
         "workload_id_v16_p4", pwd_w, sizeof(pwd_w) - 1, salt16, sizeof(salt16),
         NULL, 0, NULL, 0},
        /* 3: Argon2i with p=4 */
        {3, 65536, 4, 4, ARGON2_VERSION_NUMBER, 32, Argon2_i,
         "workload_i_p4", pwd_w, sizeof(pwd_w) - 1, salt16, sizeof(salt16),
         NULL, 0, NULL, 0},
        /* 4: Argon2d with p=4 */
        {3, 65536, 4, 4, ARGON2_VERSION_NUMBER, 32, Argon2_d,
         "workload_d_p4", pwd_w, sizeof(pwd_w) - 1, salt16, sizeof(salt16),
         NULL, 0, NULL, 0},
        /* 5: single-threaded p=1 */
        {3, 65536, 1, 1, ARGON2_VERSION_NUMBER, 32, Argon2_id,
         "workload_id_p1", pwd_w, sizeof(pwd_w) - 1, salt16, sizeof(salt16),
         NULL, 0, NULL, 0},
        /* 6: two lanes/two threads */
        {3, 65536, 2, 2, ARGON2_VERSION_NUMBER, 32, Argon2_id,
         "workload_id_p2", pwd_w, sizeof(pwd_w) - 1, salt16, sizeof(salt16),
         NULL, 0, NULL, 0},
        /* 7: eight lanes/eight threads */
        {3, 65536, 8, 8, ARGON2_VERSION_NUMBER, 32, Argon2_id,
         "workload_id_p8", pwd_w, sizeof(pwd_w) - 1, salt16, sizeof(salt16),
         NULL, 0, NULL, 0},
        /* 8: lanes != threads: must fall back to the original scheduler */
        {3, 65536, 4, 2, ARGON2_VERSION_NUMBER, 32, Argon2_id,
         "workload_id_lanes4_threads2", pwd_w, sizeof(pwd_w) - 1,
         salt16, sizeof(salt16), NULL, 0, NULL, 0},
        /* 9: small memory, p=4 (like the KAT generator but Argon2id) */
        {3, 32, 4, 4, ARGON2_VERSION_NUMBER, 32, Argon2_id,
         "small_id_p4", pwd_w, sizeof(pwd_w) - 1, salt8, sizeof(salt8),
         secret12, sizeof(secret12), ad12, sizeof(ad12)},
        /* 10: t=1 */
        {1, 1024, 4, 4, ARGON2_VERSION_NUMBER, 64, Argon2_id,
         "t1_id_p4", pwd_w, sizeof(pwd_w) - 1, salt16, sizeof(salt16),
         NULL, 0, NULL, 0},
        /* 11: t=5 */
        {5, 8192, 4, 4, ARGON2_VERSION_NUMBER, 32, Argon2_id,
         "t5_id_p4", pwd_long, sizeof(pwd_long) - 1, salt8, sizeof(salt8),
         NULL, 0, NULL, 0},
        /* 12: short password + 64-byte output */
        {2, 256, 4, 4, ARGON2_VERSION_NUMBER, 64, Argon2_id,
         "short_pwd_id_p4", (const uint8_t *)"pw", 2, salt8, sizeof(salt8),
         NULL, 0, NULL, 0},
    };
    size_t n = sizeof(cases) / sizeof(cases[0]);
    size_t i;
    int rc_total = 0;

    for (i = 0; i < n; ++i) {
        check_case *c = &cases[i];
        argon2_context ctx;
        uint8_t out[MAX_OUT];
        uint32_t j;
        int rc;

        memset(&ctx, 0, sizeof(ctx));
        ctx.out = out;
        ctx.outlen = c->outlen;
        ctx.pwd = (uint8_t *)c->pwd;
        ctx.pwdlen = (uint32_t)c->pwdlen;
        ctx.salt = (uint8_t *)c->salt;
        ctx.saltlen = (uint32_t)c->saltlen;
        ctx.secret = (uint8_t *)c->secret;
        ctx.secretlen = (uint32_t)c->secretlen;
        ctx.ad = (uint8_t *)c->ad;
        ctx.adlen = (uint32_t)c->adlen;
        ctx.t_cost = c->t_cost;
        ctx.m_cost = c->m_cost;
        ctx.lanes = c->lanes;
        ctx.threads = c->threads;
        ctx.version = c->version;
        ctx.flags = ARGON2_DEFAULT_FLAGS;

        rc = argon2_ctx(&ctx, c->type);
        printf("%-32s t=%u m=%u lanes=%u threads=%u ver=%u out=%u type=%d "
               "pwdlen=%u saltlen=%u secretlen=%u adlen=%u rc=%d ",
               c->label, c->t_cost, c->m_cost, c->lanes, c->threads,
               c->version, c->outlen, (int)c->type, (uint32_t)c->pwdlen,
               (uint32_t)c->saltlen, (uint32_t)c->secretlen,
               (uint32_t)c->adlen, rc);
        if (rc == ARGON2_OK) {
            for (j = 0; j < c->outlen; ++j) {
                printf("%02x", out[j]);
            }
        } else {
            printf("(error %d: %s)", rc, argon2_error_message(rc));
            rc_total = 1;
        }
        printf("\n");
    }

    if (rc_total == 0) {
        printf("digest_check: all %u cases produced ARGON2_OK\n",
               (unsigned)n);
    } else {
        printf("digest_check: FAILED (%u cases with errors)\n",
               (unsigned)rc_total);
    }
    return rc_total;
}
