#ifndef ANYTLS_MD5_H
#define ANYTLS_MD5_H

#include <stddef.h>
#include <stdint.h>

void anytls_md5(const uint8_t *data, size_t len, uint8_t out[16]);
void anytls_md5_hex(const uint8_t digest[16], char out[33]);

#endif
