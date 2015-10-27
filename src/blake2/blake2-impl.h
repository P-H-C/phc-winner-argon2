#ifndef PORTABLE_BLAKE2_IMPL_H
#define PORTABLE_BLAKE2_IMPL_H

#include <stdint.h>
#include <string.h>
/* Argon2 Team - Begin Code */
#include "brg-endian.h"
/* Argon2 Team - End Code */

#if defined(_MSC_VER)
#define BLAKE2_INLINE __inline
#elif defined(__GNUC__) || defined(__clang__)
#define BLAKE2_INLINE __inline__
#else
#define BLAKE2_INLINE
#endif

/* Argon2 Team - Begin Code */
#if defined(PLATFORM_BYTE_ORDER) &&                                            \
    (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN) &&                               \
    !defined(NATIVE_LITTLE_ENDIAN)
#define NATIVE_LITTLE_ENDIAN
#endif
/* Argon2 Team - End Code */

static BLAKE2_INLINE uint32_t load32(const void *src) {
#if defined(NATIVE_LITTLE_ENDIAN)
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const uint8_t *p = (const uint8_t *)src;
    uint32_t w = *p++;
    w |= (uint32_t)(*p++) << 8;
    w |= (uint32_t)(*p++) << 16;
    w |= (uint32_t)(*p++) << 24;
    return w;
#endif
}

static BLAKE2_INLINE uint64_t load64(const void *src) {
#if defined(NATIVE_LITTLE_ENDIAN)
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    const uint8_t *p = (const uint8_t *)src;
    uint64_t w = *p++;
    w |= (uint64_t)(*p++) << 8;
    w |= (uint64_t)(*p++) << 16;
    w |= (uint64_t)(*p++) << 24;
    w |= (uint64_t)(*p++) << 32;
    w |= (uint64_t)(*p++) << 40;
    w |= (uint64_t)(*p++) << 48;
    w |= (uint64_t)(*p++) << 56;
    return w;
#endif
}

static BLAKE2_INLINE void store32(void *dst, uint32_t w) {
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
#endif
}

static BLAKE2_INLINE void store64(void *dst, uint64_t w) {
#if defined(NATIVE_LITTLE_ENDIAN)
    memcpy(dst, &w, sizeof w);
#else
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
#endif
}

static BLAKE2_INLINE uint64_t load48(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    uint64_t w = *p++;
    w |= (uint64_t)(*p++) << 8;
    w |= (uint64_t)(*p++) << 16;
    w |= (uint64_t)(*p++) << 24;
    w |= (uint64_t)(*p++) << 32;
    w |= (uint64_t)(*p++) << 40;
    return w;
}

static BLAKE2_INLINE void store48(void *dst, uint64_t w) {
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
}

static BLAKE2_INLINE uint32_t rotr32(const uint32_t w, const unsigned c) {
    return (w >> c) | (w << (32 - c));
}

static BLAKE2_INLINE uint64_t rotr64(const uint64_t w, const unsigned c) {
    return (w >> c) | (w << (64 - c));
}

/* prevents compiler optimizing out memset() */
static BLAKE2_INLINE void burn(void *v, size_t n) {
    static void *(*const volatile memset_v)(void *, int, size_t) = &memset;
    memset_v(v, 0, n);
}

#endif
