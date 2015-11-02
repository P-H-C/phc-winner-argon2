# Argon2

This is the reference C implementation of Argon2, the password-hashing
function that won the [Password Hashing Competition
(PHC)](https://password-hashing.net). 

You should use Argon2 whenever you need to hash passwords for credential
storage, key derivation, or other applications.

There are two main versions of Argon2, **Argon2i** and **Argon2d**. Argon2i
is the safest against side-channel attacks, while Argon2d provides the
highest resistance against GPU cracking attacks.

Argon2i and Argon2d are parametrized by

* A **time** cost, which defines the amount of computation realized and
  therefore the execution time, given in number of iterations
* A **memory** cost, which defines the memory usage, given in kibibytes 
* A **parallelism** degree, which defines the number of parallel threads

The [Argon2 document](argon2-specs.pdf) gives detailed specs and design
rationale.

Please report bugs as issues on this repository.

## Usage

`make` builds the executable `argon2`, the static library `libargon2.a`,
and the shared library `libargon2.so` (or `libargon2.dylib` on OSX).
Make sure to run `make test` to verify that your build produces valid
results.

### Command-line utility

`argon2` is a command-line utility to test specific Argon2 instances
on your system. To show usage instructions, run
`./argon2` without arguments as
```
$ ./argon2
Usage:  ./argon2 pwd salt [-y version] [-t iterations] [-m memory] [-p parallelism]
Parameters:
        pwd             The password to hash
        salt            The salt to use, at most 16 characters
        -d              Use Argon2d instead of Argon2i (which is the default)
        -t N            Sets the number of iterations to N (default = 3)
        -m N            Sets the memory usage of 2^N KiB (default 12)
        -p N            Sets parallelism to N threads (default 4)
```
For example, to hash "password" using "somesalt" as a salt and doing 2
iterations, consuming 64 MiB, and using four parallel threads:
```
$ ./argon2 password somesalt -t 2 -m 16 -p 4
Type:           Argon2i
Iterations:     2
Memory:         65536 KiB
Parallelism:    4
$argon2i$m=65536,t=2,p=4$c29tZXNhbHQAAAAAAAAAAA$QWLzI4TY9HkL2ZTLc8g6SinwdhZewYrzz9zxCo0bkGY
0.274 seconds
```

### Library

`libargon2` provides an API to both low-level and high-level functions
for using Argon2.

The example program below hashes the string "password" with Argon2i
using the high-level API and then using the low-level API. While the
high-level API only takes input/output buffers and the two cost
parameters, the low-level API additionally takes parallelism parameters
and several others, as defined in [`src/argon2.h`](src/argon2.h).


Here the time cost `t_cost` is set to 2 iterations, the
memory cost `m_cost` is set to 2<sup>16</sup> kibibytes (64 mebibytes),
and parallelism is set to 1 (single-thread).

Compile for example as `gcc test.c libargon2.a -Isrc -o test`, if the program
below is named `test.c` and placed in the project's root directory.

```c
#include "argon2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define OUTLEN 32
#define SALTLEN 16
#define PWD "password"

int main(void)
{
    uint8_t out1[OUTLEN];
    uint8_t out2[OUTLEN];

    uint8_t salt[SALTLEN];
    memset( salt, 0x00, SALTLEN );

    uint8_t *in = (uint8_t *)strdup(PWD);
    uint32_t inlen = strlen((char *)in);

    uint32_t t_cost = 2;            // 1-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage

    // high-level API
    hash_argon2i( out1, OUTLEN, in, inlen, salt, SALTLEN, t_cost, m_cost );
    free(in);

    // low-level API
    uint32_t lanes = 1;             // lanes 1 by default
    uint32_t threads = 1;           // threads 1 by default
    in = (uint8_t *)strdup(PWD);    // was erased by previous call
    argon2_context context = {
        out2, OUTLEN, 
        in, inlen, 
        salt, SALTLEN,
        NULL, 0, /* secret data */
        NULL, 0, /* associated data */
        t_cost, m_cost, lanes, threads, 
        NULL, NULL, /* custom memory allocation / deallocation functions */
        ARGON2_DEFAULT_FLAGS /* by default the password is zeroed on exit */
    };
    argon2i( &context );
    free(in);

    for( int i=0; i<OUTLEN; ++i ) printf( "%02x", out1[i] ); printf( "\n" );
    if (memcmp(out1, out2, OUTLEN)) {
        for( int i=0; i<OUTLEN; ++i ) printf( "%02x", out2[i] ); printf( "\n" );
        printf("fail\n");
    }
    else printf("ok\n");

    return 0;
}
```

To use Argon2d instead of Argon2i call `hash_argon2d` instead of
`hash_argon2i` using the high-level API, and `argon2d` instead of
`argon2i` using the low-level API.

*Note: in this example the salt is set to the all-`0x00` string for the
sake of simplicity, but in your application you should use a random salt.*


### Benchmarks

`make bench` creates the exectuble `bench`, which measures the execution
time of various Argon2 instances:

```
$ ./bench
Argon2d 1 iterations  1 MiB 1 threads:  5.91 cpb 5.91 Mcycles
Argon2i 1 iterations  1 MiB 1 threads:  4.64 cpb 4.64 Mcycles
0.0041 seconds

Argon2d 1 iterations  1 MiB 2 threads:  2.76 cpb 2.76 Mcycles
Argon2i 1 iterations  1 MiB 2 threads:  2.87 cpb 2.87 Mcycles
0.0038 seconds

Argon2d 1 iterations  1 MiB 4 threads:  3.25 cpb 3.25 Mcycles
Argon2i 1 iterations  1 MiB 4 threads:  3.57 cpb 3.57 Mcycles
0.0048 seconds

(...)

Argon2d 1 iterations  4096 MiB 2 threads:  2.15 cpb 8788.08 Mcycles
Argon2i 1 iterations  4096 MiB 2 threads:  2.15 cpb 8821.59 Mcycles
13.0112 seconds

Argon2d 1 iterations  4096 MiB 4 threads:  1.79 cpb 7343.72 Mcycles
Argon2i 1 iterations  4096 MiB 4 threads:  2.72 cpb 11124.86 Mcycles
19.3974 seconds

(...)
```



## Intellectual property

Except for the components listed below, the Argon2 code in this
repository is copyright (c) 2015 Daniel Dinu, Dmitry Khovratovich (main
authors), Jean-Philippe Aumasson and Samuel Neves, and under
[CC0 license](https://creativecommons.org/about/cc0).

[`src/encoding.h`](src/encoding.h) is copyright (c) 2015 Thomas Pornin, and
under [CC0 license](https://creativecommons.org/about/cc0).

The BLAKE2 code in [`src/blake2/`](src/blake2) is copyright (c) Samuel
Neves, 2013-2015, and under [CC0
license](https://creativecommons.org/about/cc0).

All licenses are therefore GPL-compatible.
