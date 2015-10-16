#include "argon2.h"
#include <stdio.h>
#include <string.h>

#define OUTLEN 32
#define SALTLEN 16

int main() {
    uint8_t out[OUTLEN];
    uint8_t pwd[] = "password";
    uint8_t salt[SALTLEN];
    
    memset(salt, 0x00, SALTLEN);

    const uint32_t t_cost = 5;
    const uint32_t m_cost = 1 << 10;
    const uint32_t lanes = 4;
    const uint32_t threads = 4;

    Argon2_Context context = {out, OUTLEN, pwd, sizeof(pwd), salt, sizeof(salt), NULL, 0, NULL, 0, t_cost, m_cost, lanes, threads, NULL, NULL, false, false, false, false};

    Argon2d( &context );

    for(int i=0; i<OUTLEN; ++i)
        printf("%02x", out[i]);
    printf("\n");

    return 0;
}
