#include "argon2.h"
#include <stdio.h>
#include <string.h>

int main() {
    uint8_t out[32];
    uint8_t pwd[] = "password";
    uint8_t salt[16];
    memset(salt, 0x00, 16);

    // Argon2i with 1 pass and ~50MiB memory usage
    hash(out, 32, pwd, strlen(pwd), salt, 16, 1, 50*(1<<10));

    for(int i=0; i<32; ++i) printf("%02x", out[i]); printf("\n");

    return 0;
}
