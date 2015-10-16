/*
 * Argon2 source code package
 *
 * Written by Daniel Dinu and Dmitry Khovratovich, 2015
 *
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "time.h"
#include "argon2.h"
#ifdef _MSC_VER
#include "intrin.h"
#endif
/* Enable timing measurements */
#define _MEASURE

#define T_COST_DEF 3
#define M_COST_DEF (1<<18)
#define LANES_DEF 4
#define THREADS_DEF 4

#define UNUSED_PARAMETER(x) (void)(x)

static inline uint64_t rdtsc( void )
{
#ifdef _MSC_VER
    return __rdtsc();
#else
    uint64_t rax, rdx;
    __asm__ __volatile__ ( "rdtsc" : "=a" ( rax ), "=d" ( rdx ) : : );
    return ( rdx << 32 ) | rax;
#endif
}

/*
 * Custom allocate memory
 */
int CustomAllocateMemory( uint8_t **memory, size_t length )
{
    *memory = ( uint8_t * )malloc( length );

    if ( !*memory )
    {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    return ARGON2_OK;
}

/*
 * Custom free memory
 */
void CustomFreeMemory( uint8_t *memory, size_t length )
{
    UNUSED_PARAMETER( length );

    if ( memory )
    {
        free( memory );
    }
}


void usage( const char *cmd )
{
    printf( "usage: %s mode [parameters]\n", cmd );
    printf( "Mode:\n" );
    printf( "\tr\trun Argon2 with the selected parameters\n" );
    printf( "\tg\tgenerates test vectors for given Argon2 type\n" );
    printf( "\tb\tbenchmarks various Argon2 versions\n" );
    printf( "Parameters (for run mode):\n" );
    printf( "\t-y, --type [d | i | id | ds]\n" );
    printf( "\t-t, --tcost [time cost in 0..2^24, default %d]\n", T_COST_DEF );
    printf( "\t-m, --mcost [base 2 log of memory cost in 0..23, default %d]\n", M_COST_DEF );
    printf( "\t-l, --lanes [number of lanes in %u..%u, default %d]\n", ARGON2_MIN_LANES, ARGON2_MAX_LANES, LANES_DEF );
    printf( "\t-p, --threads [number of threads in %u..%u, default %d]\n", ARGON2_MIN_THREADS, ARGON2_MAX_THREADS, THREADS_DEF );
}


void fatal( const char *error )
{
    fprintf( stderr, "error: %s\n", error );
    exit( 1 );
}

void print_bytes(const void *s, size_t len)
{
  for(size_t i = 0; i < len; i++)
  {
    printf("%02x", ((const unsigned char *) s)[i] & 0xff);
  }
  printf("\n");
}


/*
 * Benchmarks Argon2 with salt length 16, password length 32, t_cost 3, and different threads and m_cost
 */
void Benchmark()
{
    const uint32_t inlen = 16;
    const unsigned outlen=16;
    unsigned char out[outlen];
    unsigned char pwd_array[inlen];
    unsigned char salt_array[inlen];

    uint32_t t_cost = 1;

    memset( pwd_array, 0, inlen );
    memset( salt_array, 1, inlen );
    uint32_t thread_test[6] = {1, 2, 4, 6, 8, 16};

    uint32_t m_cost;

    for ( m_cost = ( uint32_t ) 1 << 10; m_cost <= ( uint32_t ) 1 << 22; m_cost *= 2 )
    {
        uint32_t i;

        for ( i=0; i <6; ++i )
        {
            uint32_t thread_n = thread_test[i];
#ifdef _MEASURE
            uint64_t start_cycles, stop_cycles, stop_cycles_i, stop_cycles_di, stop_cycles_ds;

            clock_t start_time = clock();
            start_cycles = rdtsc();
#endif

            Argon2_Context context = {out, outlen, pwd_array, inlen, salt_array, inlen,
                                      NULL, 0, NULL, 0, t_cost, m_cost, thread_n, thread_n, NULL, NULL, false, false, false, false
                                     };
            Argon2d( &context );

#ifdef _MEASURE
            stop_cycles = rdtsc();
#endif
            Argon2i( &context );
#ifdef _MEASURE
            stop_cycles_i = rdtsc();
#endif
            Argon2id( &context );
#ifdef _MEASURE
            stop_cycles_di = rdtsc();
#endif
            Argon2ds( &context );
#ifdef _MEASURE
            stop_cycles_ds = rdtsc();
            clock_t stop_time = clock();

            uint64_t delta_d = ( stop_cycles - start_cycles ) / ( m_cost );
            uint64_t delta_i = ( stop_cycles_i - stop_cycles ) / ( m_cost );
            uint64_t delta_id = ( stop_cycles_di - stop_cycles_i ) / m_cost;
            uint64_t delta_ds = ( stop_cycles_ds - stop_cycles_di ) / m_cost;
            float mcycles_d = ( float ) ( stop_cycles - start_cycles ) / ( 1 << 20 );
            float mcycles_i = ( float ) ( stop_cycles_i - stop_cycles ) / ( 1 << 20 );
            float mcycles_id = ( float ) ( stop_cycles_di - stop_cycles_i ) / ( 1 << 20 );
            float mcycles_ds = ( float ) ( stop_cycles_ds - stop_cycles_di ) / ( 1 << 20 );
            printf( "Argon2d %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, ( float ) delta_d / 1024, mcycles_d );
            printf( "Argon2i %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, ( float ) delta_i / 1024, mcycles_i );
            printf( "Argon2id %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, ( float ) delta_id / 1024, mcycles_id );
            printf( "Argon2ds %d pass(es)  %d Mbytes %d threads:  %2.2f cpb %2.2f Mcycles \n", t_cost, m_cost >> 10, thread_n, ( float ) delta_ds / 1024, mcycles_ds );

            float run_time = ( ( float ) stop_time - start_time ) / ( CLOCKS_PER_SEC );
            printf( "%2.4f seconds\n\n", run_time );
#endif
        }
    }
}

/*Call Argon2 with default salt and password and user-defined parameter values.*/

void Run( uint8_t *out, uint32_t t_cost, uint32_t m_cost, uint32_t lanes, uint32_t threads,const char *type, bool print )
{
#ifdef _MEASURE
    uint64_t start_cycles, stop_cycles;

    clock_t start_time = clock();
    start_cycles = rdtsc();
#endif

    /*Fixed parameters*/
    const unsigned out_length = 32;
    const unsigned pwd_length = 32;
    const unsigned salt_length = 16;
    const unsigned secret_length = 8;
    const unsigned ad_length = 12;
    bool clear_memory = false;
    bool clear_secret = false;
    bool clear_password = false;
    uint8_t pwd[pwd_length];
    uint8_t salt[salt_length];
    uint8_t secret[secret_length];
    uint8_t ad[ad_length];

    UNUSED_PARAMETER( threads );

    memset( pwd, 1, pwd_length );
    memset( salt, 2, salt_length );
    memset( secret, 3, secret_length );
    memset( ad, 4, ad_length );

    Argon2_Context context= {out, out_length, pwd, pwd_length, salt, salt_length,
                             secret, secret_length, ad, ad_length, t_cost, m_cost, lanes, lanes,
                             NULL, NULL,
                             clear_password, clear_secret, clear_memory, print
                            };
    printf("Argon2%s with\n", type);
    printf("\tt_cost = %d\n", t_cost);
    printf("\tm_cost = %d\n", m_cost);
    printf("\tpassword = "); print_bytes(pwd, pwd_length);
    printf("\tsalt = "); print_bytes(salt, salt_length);

    if ( !strcmp( type,"d" ) )  Argon2d( &context );
    else if ( !strcmp( type,"i" ) ) Argon2i( &context );
    else if ( !strcmp( type,"ds" ) ) Argon2ds( &context );
    else if ( !strcmp( type,"id" ) ) Argon2id( &context );
    else fatal( "wrong Argon2 type" );


#ifdef _MEASURE
    stop_cycles = rdtsc();
    clock_t finish_time = clock();


    float run_time = ( ( float ) finish_time - start_time ) / ( CLOCKS_PER_SEC );
    printf( "%2.3f seconds ", run_time );

    float mcycles = ( float ) ( stop_cycles - start_cycles ) / ( 1 << 20 );
    printf( "(%.3f mebicycles)\n", mcycles );
#endif

    printf("hash = "); print_bytes(out, out_length);
}

void GenerateTestVectors( const char *type )
{
    const unsigned out_length = 32;
    const unsigned pwd_length = 32;
    const unsigned salt_length = 16;
    const unsigned secret_length = 8;
    const unsigned ad_length = 12;
    bool clear_memory = false;
    bool clear_secret = false;
    bool clear_password = false;
    bool print_internals = true;
    unsigned char out[out_length];
    unsigned char pwd[pwd_length];
    unsigned char salt[salt_length];
    unsigned char secret[secret_length];
    unsigned char ad[ad_length];
    const AllocateMemoryCallback myown_allocator = NULL;
    const FreeMemoryCallback myown_deallocator = NULL;

    unsigned t_cost = 3;
    unsigned m_cost = 16;
    unsigned lanes = 4;

    memset( pwd, 1, pwd_length );
    memset( salt, 2, salt_length );
    memset( secret, 3, secret_length );
    memset( ad, 4, ad_length );

    printf( "Generate test vectors for Argon2%s in file \"%s\".\n", type, ARGON2_KAT_FILENAME );

    Argon2_Context context= {out, out_length, pwd, pwd_length, salt, salt_length,
                             secret, secret_length, ad, ad_length, t_cost, m_cost, lanes, lanes,
                             myown_allocator, myown_deallocator,
                             clear_password, clear_secret, clear_memory, print_internals
                            };

    if ( !strcmp( type,"d" ) ) Argon2d( &context );
    else if ( !strcmp( type,"i" ) ) Argon2i( &context );
    else if ( !strcmp( type,"ds" ) ) Argon2ds( &context );
    else if ( !strcmp( type,"id" ) ) Argon2id( &context );
    else  fatal( "wrong Argon2 type" );
}

int main( int argc, char *argv[] )
{

    unsigned char out[32];
    uint32_t m_cost = M_COST_DEF;
    uint32_t t_cost = T_COST_DEF;
    uint32_t lanes = LANES_DEF;
    uint32_t threads = THREADS_DEF;

    bool generate_test_vectors = false;
    const char *type= "d";

    remove( ARGON2_KAT_FILENAME );

    if ( argc == 1 )
    {
        usage( argv[0] );
        return 1;
    }

    for ( int i = 1; i < argc; i++ )
    {
        char *a = argv[i];

        if ( !strcmp( a, "-m" ) || !strcmp( a, "--mcost" ) )
        {
            if ( i < argc - 1 )
            {
                i++;
                m_cost = ( uint8_t ) 1 << ( ( uint8_t )atoi( argv[i] ) % 24 );
                continue;
            }
            else fatal( "missing memory cost argument" );
        }
        else if ( !strcmp( a, "-t" ) || !strcmp( a, "--tcost" ) )
        {
            if ( i < argc - 1 )
            {
                i++;
                t_cost = atoi( argv[i] ) & 0xffffff;
                continue;
            }
            else fatal( "missing time cost argument" );
        }
        else if ( !strcmp( a, "-p" ) || !strcmp( a, "--threads" ) )
        {
            if ( i < argc - 1 )
            {
                i++;
                threads = atoi( argv[i] ) % ARGON2_MAX_THREADS;
                continue;
            }
            else fatal( "missing threads argument" );
        }
        else if ( !strcmp( a, "-l" ) || !strcmp( a, "--lanes" ) )
        {
            if ( i < argc - 1 )
            {
                i++;
                lanes = atoi( argv[i] ) % ARGON2_MAX_LANES;
                continue;
            }
            else fatal( "missing lanes argument" );
        }
        else if ( !strcmp( a, "-y" ) || !strcmp( a, "--type" ) )
        {
            if ( i < argc - 1 )
            {
                i++;
                type = argv[i];
                continue;
            }
            else fatal( "missing type argument" );
        }
        else if ( !strcmp( a, "r" ))
        {
            generate_test_vectors = false;
            continue;
        }
        else if ( !strcmp( a, "g" ))
        {
            generate_test_vectors = true;
            continue;
        }
        else if ( !strcmp( a, "b" ))
        {
            Benchmark();
            return 0;
        }
        else fatal("unknown argument");
    }

    if ( generate_test_vectors )
    {
        GenerateTestVectors( type );
        return 0;
    }

    Run( out,  t_cost, m_cost, lanes, threads, type, generate_test_vectors );

    return 0;
}
