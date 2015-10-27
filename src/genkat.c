#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "argon2.h"
#include "core.h"


void initial_kat(const uint8_t *blockhash, const argon2_context *context,
                 argon2_type type) {
    unsigned i;
    FILE *fp = fopen(ARGON2_KAT_FILENAME, "a+");

    if (fp && blockhash != NULL && context != NULL) {
        fprintf(fp, "=======================================");

        switch (type) {
        case Argon2_d:
            fprintf(fp, "Argon2d\n");
            break;

        case Argon2_i:
            fprintf(fp, "Argon2i\n");
            break;

        default:
            break;
        }

        fprintf(
            fp, "Iterations: %d, Memory: %d KBytes, Parallelism: %d lanes, Tag "
                "length: %d bytes\n",
            context->t_cost, context->m_cost, context->lanes, context->outlen);

        fprintf(fp, "Password[%d]: ", context->pwdlen);

        if (context->flags & ARGON2_CLEAR_PASSWORD) {
            fprintf(fp, "CLEARED\n");
        } else {
            for (i = 0; i < context->pwdlen; ++i) {
                fprintf(fp, "%2.2x ", ((unsigned char *)context->pwd)[i]);
            }

            fprintf(fp, "\n");
        }

        fprintf(fp, "Salt[%d]: ", context->saltlen);

        for (i = 0; i < context->saltlen; ++i) {
            fprintf(fp, "%2.2x ", ((unsigned char *)context->salt)[i]);
        }

        fprintf(fp, "\n");

        fprintf(fp, "Secret[%d]: ", context->secretlen);

        if (context->flags & ARGON2_CLEAR_SECRET) {
            fprintf(fp, "CLEARED\n");
        } else {
            for (i = 0; i < context->secretlen; ++i) {
                fprintf(fp, "%2.2x ", ((unsigned char *)context->secret)[i]);
            }

            fprintf(fp, "\n");
        }

        fprintf(fp, "Associated data[%d]: ", context->adlen);

        for (i = 0; i < context->adlen; ++i) {
            fprintf(fp, "%2.2x ", ((unsigned char *)context->ad)[i]);
        }

        fprintf(fp, "\n");

        fprintf(fp, "Pre-hashing digest: ");

        for (i = 0; i < ARGON2_PREHASH_DIGEST_LENGTH; ++i) {
            fprintf(fp, "%2.2x ", ((unsigned char *)blockhash)[i]);
        }

        fprintf(fp, "\n");

        fclose(fp);
    }
}

void print_tag(const void *out, uint32_t outlen) {
    FILE *fp = fopen(ARGON2_KAT_FILENAME, "a+");
    unsigned i;
    if (fp && out != NULL) {
        fprintf(fp, "Tag: ");

        for (i = 0; i < outlen; ++i) {
            fprintf(fp, "%2.2x ", ((uint8_t *)out)[i]);
        }

        fprintf(fp, "\n");

        fclose(fp);
    }
}

void internal_kat(const argon2_instance_t *instance, uint32_t pass) {
    FILE *fp = fopen(ARGON2_KAT_FILENAME, "a+");

    if (fp && instance != NULL) {
        uint32_t i, j;
        fprintf(fp, "\n After pass %d:\n", pass);

        for (i = 0; i < instance->memory_blocks; ++i) {
            uint32_t how_many_words =
                (instance->memory_blocks > ARGON2_WORDS_IN_BLOCK)
                    ? 1
                    : ARGON2_WORDS_IN_BLOCK;

            for (j = 0; j < how_many_words; ++j)
                fprintf(fp, "Block %.4d [%3d]: %016" PRIx64 "\n", i, j, instance->memory[i].v[j]);
        }

        fclose(fp);
    }
}

static void fatal(const char *error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

static void generate_testvectors(const char *type) {
#define TEST_OUTLEN 32
#define TEST_PWDLEN 32
#define TEST_SALTLEN 16
#define TEST_SECRETLEN 8
#define TEST_ADLEN 12
    argon2_context context;

    unsigned char out[TEST_OUTLEN];
    unsigned char pwd[TEST_PWDLEN];
    unsigned char salt[TEST_SALTLEN];
    unsigned char secret[TEST_SECRETLEN];
    unsigned char ad[TEST_ADLEN];
    const allocate_fptr myown_allocator = NULL;
    const deallocate_fptr myown_deallocator = NULL;

    unsigned t_cost = 3;
    unsigned m_cost = 16;
    unsigned lanes = 4;

    memset(pwd, 1, TEST_OUTLEN);
    memset(salt, 2, TEST_SALTLEN);
    memset(secret, 3, TEST_SECRETLEN);
    memset(ad, 4, TEST_ADLEN);

    printf("Generating test vectors for Argon2%s in file \"%s\".\n", type,
           ARGON2_KAT_FILENAME);

    context.out = out;
    context.outlen = TEST_OUTLEN;
    context.pwd = pwd;
    context.pwdlen = TEST_PWDLEN;
    context.salt = salt;
    context.saltlen = TEST_SALTLEN;
    context.secret = secret;
    context.secretlen = TEST_SECRETLEN;
    context.ad = ad;
    context.adlen = TEST_ADLEN;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = lanes;
    context.threads = lanes;
    context.allocate_cbk = myown_allocator;
    context.free_cbk = myown_deallocator;
    context.flags = 0;

#undef TEST_OUTLEN
#undef TEST_PWDLEN
#undef TEST_SALTLEN
#undef TEST_SECRETLEN
#undef TEST_ADLEN

    if (!strcmp(type, "d")) {
        printf("Generating test vectors for Argon2d in file \"%s\".\n",
               ARGON2_KAT_FILENAME);
        argon2d(&context);
    } else if (!strcmp(type, "i")) {
        printf("Generating test vectors for Argon2i in file \"%s\".\n",
               ARGON2_KAT_FILENAME);
        argon2i(&context);
    } else
        fatal("wrong Argon2 type");
}

int main(int argc, char *argv[]) {
    const char * type = (argc > 1) ? argv[1] : "i";
    remove(ARGON2_KAT_FILENAME);
    generate_testvectors(type);
    return 0;
}
