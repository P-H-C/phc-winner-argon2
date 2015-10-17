#include "argon2.h"
#include <stdio.h>
#include <string.h>

#define OUTLEN 32
#define SALTLEN 16
#define PWD "password"

int main()
{
    uint8_t out1[OUTLEN];
    uint8_t out2[OUTLEN];

    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

    uint8_t *in = (uint8_t *)strdup(PWD);
    uint32_t inlen = strlen((char *)in);

    uint32_t t_cost = 2;            // 1-pass computation
    uint32_t m_cost = 50*(1<<10);   // 50 mebibytes memory usage

    // high-level API
    hashpwd( out1, OUTLEN, in, inlen, salt, SALTLEN, t_cost, m_cost );

    // low-level API
    uint32_t lanes = 1;             // lanes 1 by default
    uint32_t threads = 1;           // threads 1 by default
    in = (uint8_t *)strdup(PWD);    // cos' erased by previous call
    Argon2_Context context = {out2, OUTLEN, in, inlen, salt, SALTLEN, \
        NULL, 0, NULL, 0, t_cost, m_cost, lanes, threads, NULL, NULL, \
        true, true, true, false };
    argon2i( &context );

    for( int i=0; i<OUTLEN; ++i ) printf( "%02x", out1[i] ); printf( "\n" );
    if (memcmp(out1, out2, OUTLEN)) {
        for( int i=0; i<OUTLEN; ++i ) printf( "%02x", out2[i] ); printf( "\n" );
        printf("fail\n");
    }
    else printf("ok\n");

    return 0;
}
