#include "argon2.h"
#include <stdio.h>
#include <string.h>

#define OUTLEN 32       // 32-byte hash
#define SALTLEN 16      // 16-byte salt

int main()
{
    uint8_t out[OUTLEN];
    uint8_t pwd[] = "password";
    uint32_t pwdlen = strlen( (char *)pwd );
    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

    uint32_t t_cost = 1;            // 1-pass computation
    uint32_t m_cost = 50*(1<<10);   // 50 mebibytes memory usage

    // Argon2i, with default parallelism 1 (serial, single-thread)
    hashpwd( out, OUTLEN, pwd, pwdlen, salt, SALTLEN, t_cost, m_cost );

    for( int i=0; i<32; ++i ) printf( "%02x", out[i] ); printf( "\n" );
    
    uint32_t lanes = 1;    
    uint32_t threads = 1;    

    Argon2_Context context = {out, OUTLEN, pwd, pwdlen, salt, SALTLEN, \
        NULL, 0, NULL, 0, t_cost, m_cost, lanes, threads, NULL, NULL, \
        true, true, true, false };

    argon2d( &context );

    for( int i=0; i<32; ++i ) printf( "%02x", context.out[i] ); printf( "\n" );

    return 0;
}
