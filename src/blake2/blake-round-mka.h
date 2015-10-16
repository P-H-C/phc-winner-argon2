#pragma once

#ifndef __BLAKE_ROUND_MKA_H__
#define __BLAKE_ROUND_MKA_H__


#define G(a,b,c,d) \
	a = fBlaMka(a, b) ; \
	d = rotr64(d ^ a, 32); \
	c = fBlaMka(c, d); \
	b = rotr64(b ^ c, 24); \
	a = fBlaMka(a, b) ; \
	d = rotr64(d ^ a, 16); \
	c = fBlaMka(c, d); \
	b = rotr64(b ^ c, 63); 

#define BLAKE2_ROUND_NOMSG(v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15)  \
	G(v0, v4, v8, v12); \
	G(v1, v5, v9, v13); \
	G(v2, v6, v10, v14); \
	G(v3, v7, v11, v15); \
	G(v0, v5, v10, v15); \
	G(v1, v6, v11, v12); \
	G(v2, v7, v8, v13); \
	G(v3, v4, v9, v14); 


/*designed by the Lyra PHC team */
static inline uint64_t fBlaMka(uint64_t x, uint64_t y)
{
	uint32_t lessX = (uint32_t)x;
	uint32_t lessY = (uint32_t)y;

	uint64_t lessZ = (uint64_t)lessX;
	lessZ = lessZ * lessY;
	lessZ = lessZ << 1;

	uint64_t z = lessZ + x + y;

	return z;
}


#endif
