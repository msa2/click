#ifndef _OCTEON_HMAC_H
#define _OCTEON_HMAC_H

unsigned char * HMAC( unsigned char *key, int key_len,unsigned char *d, size_t n, unsigned char *md,unsigned int *md_len);

#endif
