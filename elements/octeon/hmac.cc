// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * Copyright (c) 2012 Technical Research Centre of Finland (VTT)
 *
 * Markku.Savela@vtt.fi
 */

#include <click/config.h>
#include <click/error.hh>
#include <click/args.hh>
#include <click/packet_anno.hh>
#include <click/standard/scheduleinfo.hh>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include "cvmx-config.h"
#include "cvmx.h"

#include "hmac.hh"


#define SHA_LBLOCK	16		// ...size in 32 bit words
#define SHA_CBLOCK	(SHA_LBLOCK*4)	// ...size in characters
#define SHA_XBLOCK	(SHA_CBLOCK/8)	// ...size in 64 bit words
#define SHA_LAST_BLOCK  (SHA_CBLOCK-8)
#define SHA_DIGEST_LENGTH 20

typedef union {
    uint64_t d[SHA_XBLOCK];
    uint8_t c[SHA_CBLOCK];
} block_t;

typedef struct
{
    block_t data;
    size_t used;
    uint64_t total;
} SHA1_OCTEON_ctx;

#define INIT_DATA_IV0 (uint64_t)0x67452301efcdab89ULL
#define INIT_DATA_IV1 (uint64_t)0x98badcfe10325476ULL
#define INIT_DATA_IV2 (uint64_t)0xc3d2e1f000000000ULL


static void SHA1_OCTEON_init(SHA1_OCTEON_ctx *c)
{
    CVMX_MT_HSH_IV(INIT_DATA_IV0, 0);
    CVMX_MT_HSH_IV(INIT_DATA_IV1, 1);
    CVMX_MT_HSH_IV(INIT_DATA_IV2, 2);
    c->used = 0;
    c->total = 0;
}

static void SHA1_OCTEON_update(SHA1_OCTEON_ctx *c, const unsigned char *data, size_t len)
{
    c->total += len;

    if (c->used) {
	size_t fill = SHA_CBLOCK - c->used;
	if (fill > len)
	    fill = len;
	memcpy(c->data.c + c->used, data, fill);
	c->used += fill;
	len -= fill;
	data += fill;
	if (c->used == SHA_CBLOCK) {
	    CVMX_MT_HSH_DAT(c->data.d[0], 0);
	    CVMX_MT_HSH_DAT(c->data.d[1], 1);
	    CVMX_MT_HSH_DAT(c->data.d[2], 2);
	    CVMX_MT_HSH_DAT(c->data.d[3], 3);
	    CVMX_MT_HSH_DAT(c->data.d[4], 4);
	    CVMX_MT_HSH_DAT(c->data.d[5], 5);
	    CVMX_MT_HSH_DAT(c->data.d[6], 6);
	    CVMX_MT_HSH_STARTSHA(c->data.d[7]);
	    c->used = 0;
	}
    }
    // Either c->used == 0 or len == 0!

    if ((((uint64_t)data) & 0x7) == 0) {
	// 64-bit aligned 
	const uint64_t *p = (const uint64_t *)data;

	while (len >= SHA_CBLOCK) {
	    CVMX_MT_HSH_DAT(p[0], 0);
	    CVMX_MT_HSH_DAT(p[1], 1);
	    CVMX_MT_HSH_DAT(p[2], 2);
	    CVMX_MT_HSH_DAT(p[3], 3);
	    CVMX_MT_HSH_DAT(p[4], 4);
	    CVMX_MT_HSH_DAT(p[5], 5);
	    CVMX_MT_HSH_DAT(p[6], 6);
	    CVMX_MT_HSH_STARTSHA(p[7]);
	    len -= SHA_CBLOCK;
	    p += SHA_XBLOCK;
	}
	data = (unsigned char *)p;
    } else {
	// Non-aligned slow path
	uint64_t blob[SHA_XBLOCK];
	//click_chatter("HMAC: slow path %llx len=%u", (long long unsigned int)p, (unsigned int)len);
	while (len >= SHA_CBLOCK) {
	    memcpy(blob, data, SHA_CBLOCK);

	    CVMX_MT_HSH_DAT(blob[0], 0);
	    CVMX_MT_HSH_DAT(blob[1], 1);
	    CVMX_MT_HSH_DAT(blob[2], 2);
	    CVMX_MT_HSH_DAT(blob[3], 3);
	    CVMX_MT_HSH_DAT(blob[4], 4);
	    CVMX_MT_HSH_DAT(blob[5], 5);
	    CVMX_MT_HSH_DAT(blob[6], 6);
	    CVMX_MT_HSH_STARTSHA(blob[7]);
	    len -= SHA_CBLOCK;
	    data += SHA_CBLOCK;
	}
    }
    if (len) {
	// If we get here, c->used == 0 and len < SHA_CBLOCK
	memcpy(c->data.c, data, len);
	c->used = len;
    }
}

void SHA1_OCTEON_final(unsigned char *digest, SHA1_OCTEON_ctx *c)
{
    uint64_t iv[SHA_XBLOCK];

    c->data.c[c->used++] = 0x80;
    if (c->used > SHA_LAST_BLOCK) {
	memset(c->data.c+c->used, 0, SHA_CBLOCK - c->used);
	CVMX_MT_HSH_DAT(c->data.d[0], 0);
	CVMX_MT_HSH_DAT(c->data.d[1], 1);
	CVMX_MT_HSH_DAT(c->data.d[2], 2);
	CVMX_MT_HSH_DAT(c->data.d[3], 3);
	CVMX_MT_HSH_DAT(c->data.d[4], 4);
	CVMX_MT_HSH_DAT(c->data.d[5], 5);
	CVMX_MT_HSH_DAT(c->data.d[6], 6);
	CVMX_MT_HSH_STARTSHA(c->data.d[7]);
	memset(c->data.c, 0, SHA_LAST_BLOCK);
    } else {
	memset(c->data.c+c->used, 0, SHA_LAST_BLOCK - c->used);
    }

    CVMX_MT_HSH_DAT(c->data.d[0], 0);
    CVMX_MT_HSH_DAT(c->data.d[1], 1);
    CVMX_MT_HSH_DAT(c->data.d[2], 2);
    CVMX_MT_HSH_DAT(c->data.d[3], 3);
    CVMX_MT_HSH_DAT(c->data.d[4], 4);
    CVMX_MT_HSH_DAT(c->data.d[5], 5);
    CVMX_MT_HSH_DAT(c->data.d[6], 6);
    CVMX_MT_HSH_STARTSHA(c->total*8);

    CVMX_MF_HSH_IV(iv[0], 0);
    CVMX_MF_HSH_IV(iv[1], 1);
    CVMX_MF_HSH_IV(iv[2], 2);
    memcpy(digest, iv, SHA_DIGEST_LENGTH);
}

static void sha1_hash(const unsigned char *d, size_t n, unsigned char *digest)
{
    SHA1_OCTEON_ctx c;
    SHA1_OCTEON_init(&c);
    SHA1_OCTEON_update(&c, d, n);
    SHA1_OCTEON_final(digest, &c);
}


unsigned char *HMAC(unsigned char *key, int key_len,unsigned char *d, size_t n, unsigned char *md,unsigned int *md_len)
{
    union {
	block_t u64;
	unsigned char pad[SHA_CBLOCK];
    } i;
    union {
	block_t u64;
	struct {
	    unsigned char pad[SHA_CBLOCK];
	    unsigned char digest[SHA_DIGEST_LENGTH];
	};
    } o;

    if (!key || !md || !md_len) {
	click_chatter("HMAC: bad call");
	return NULL; // .. ignore bad calls
    }

    if (key_len > SHA_CBLOCK) {
	click_chatter("HMAC: long key = %d", key_len);
	sha1_hash(key, key_len, o.digest);
	key = o.digest;
	key_len = SHA_DIGEST_LENGTH;
    }
    memset(o.pad, 0, sizeof(o.pad));
    memcpy(o.pad, key, key_len);
    memcpy(i.pad, o.pad, sizeof(i.pad));
    for (size_t k = 0; k < sizeof(i.pad); ++k)
	{
	    i.pad[k] ^= 0x36;
	    o.pad[k] ^= 0x5c;
	}

    SHA1_OCTEON_ctx c;
    SHA1_OCTEON_init(&c);
    SHA1_OCTEON_update(&c, i.pad, sizeof(i.pad));
    SHA1_OCTEON_update(&c, d, n);
    SHA1_OCTEON_final(o.digest, &c);
    SHA1_OCTEON_init(&c);
    SHA1_OCTEON_update(&c, o.pad, sizeof(o.pad) + sizeof(o.digest));
    SHA1_OCTEON_final(o.digest, &c);
    memcpy(md, o.digest, *md_len < SHA_DIGEST_LENGTH ? *md_len : SHA_DIGEST_LENGTH);
    return md;
}
