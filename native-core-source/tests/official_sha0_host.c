/* Test-only extraction of the official fixed-revision SHA-0 implementation.
 * Original BSD notices retained below; no production cryptography replaced. */
typedef unsigned char UCHAR;
typedef unsigned int UINT;
typedef unsigned long long UINT64;
typedef __SIZE_TYPE__ size_t;
void *memcpy(void *destination, const void *source, size_t count) {
    unsigned char *d = destination; const unsigned char *s = source;
    for (size_t i = 0; i < count; i++) d[i] = s[i];
    return destination;
}
/////////////////////////
// SHA0 implementation //
/////////////////////////

// Source codes from:
//  https://android.googlesource.com/platform/system/core/+/81df1cc77722000f8d0025c1ab00ced123aa573c/libmincrypt/sha.c
//  https://android.googlesource.com/platform/system/core/+/81df1cc77722000f8d0025c1ab00ced123aa573c/include/mincrypt/hash-internal.h
//  https://android.googlesource.com/platform/system/core/+/81df1cc77722000f8d0025c1ab00ced123aa573c/include/mincrypt/sha.h

/*
 * Copyright 2013 The Android Open Source Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Google Inc. nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Google Inc. ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL Google Inc. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#define rol(bits, value) (((value) << (bits)) | ((value) >> (32 - (bits))))

typedef struct MY_SHA0_CTX {
//	const HASH_VTAB * f;
	UINT64 count;
	UCHAR buf[64];
	UINT state[8];  // upto SHA2
} MY_SHA0_CTX;

#define MY_SHA0_DIGEST_SIZE 20

static void MY_SHA0_Transform(MY_SHA0_CTX* ctx) {
	UINT W[80];
	UINT A, B, C, D, E;
	UCHAR* p = ctx->buf;
	int t;
	for(t = 0; t < 16; ++t) {
		UINT tmp =  *p++ << 24;
		tmp |= *p++ << 16;
		tmp |= *p++ << 8;
		tmp |= *p++;
		W[t] = tmp;
	}
	for(; t < 80; t++) {
		//W[t] = rol(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
		W[t] = (1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
	}
	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	for(t = 0; t < 80; t++) {
		UINT tmp = rol(5,A) + E + W[t];
		if (t < 20)
			tmp += (D^(B&(C^D))) + 0x5A827999;
		else if ( t < 40)
			tmp += (B^C^D) + 0x6ED9EBA1;
		else if ( t < 60)
			tmp += ((B&C)|(D&(B|C))) + 0x8F1BBCDC;
		else
			tmp += (B^C^D) + 0xCA62C1D6;
		E = D;
		D = C;
		C = rol(30,B);
		B = A;
		A = tmp;
	}
	ctx->state[0] += A;
	ctx->state[1] += B;
	ctx->state[2] += C;
	ctx->state[3] += D;
	ctx->state[4] += E;
}
void MY_SHA0_init(MY_SHA0_CTX* ctx) {
	//ctx->f = &SHA_VTAB;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
	ctx->count = 0;
}
void MY_SHA0_update(MY_SHA0_CTX* ctx, const void* data, int len) {
	int i = (int) (ctx->count & 63);
	const UCHAR* p = (const UCHAR*)data;
	ctx->count += len;
	while (len--) {
		ctx->buf[i++] = *p++;
		if (i == 64) {
			MY_SHA0_Transform(ctx);
			i = 0;
		}
	}
}
const UCHAR* MY_SHA0_final(MY_SHA0_CTX* ctx) {
	UCHAR *p = ctx->buf;
	UINT64 cnt = ctx->count * 8;
	int i;
	MY_SHA0_update(ctx, (UCHAR*)"\x80", 1);
	while ((ctx->count & 63) != 56) {
		MY_SHA0_update(ctx, (UCHAR*)"\0", 1);
	}
	for (i = 0; i < 8; ++i) {
		UCHAR tmp = (UCHAR) (cnt >> ((7 - i) * 8));
		MY_SHA0_update(ctx, &tmp, 1);
	}
	for (i = 0; i < 5; i++) {
		UINT tmp = ctx->state[i];
		*p++ = tmp >> 24;
		*p++ = tmp >> 16;
		*p++ = tmp >> 8;
		*p++ = tmp >> 0;
	}
	return ctx->buf;
}
/* Convenience function */
const UCHAR* MY_SHA0_hash(const void* data, int len, UCHAR* digest) {
	MY_SHA0_CTX ctx;
	MY_SHA0_init(&ctx);
	MY_SHA0_update(&ctx, data, len);
	memcpy(digest, MY_SHA0_final(&ctx), MY_SHA0_DIGEST_SIZE);
	return digest;
}
static unsigned char *Internal_SHA0(const unsigned char *d, size_t n, unsigned char *md)
{
	return (unsigned char *)MY_SHA0_hash(d, (int)n, md);
}



__declspec(dllexport) void probeHash(const void *data, int len, unsigned char digest[20]) {
    MY_SHA0_hash(data, len, digest);
}