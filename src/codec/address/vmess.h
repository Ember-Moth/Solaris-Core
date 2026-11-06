#ifndef SOLARIS_VMESS_ADDRESS_H
#define SOLARIS_VMESS_ADDRESS_H
#include "contracts/io/address.h"

/* VMess/VLESS/XUDP address: port first, then type 1/2/3 and address. */
solaris_status_t solaris_vmess_address_write(const solaris_address_t *, uint8_t *, size_t, size_t *);
solaris_status_t solaris_vmess_address_read(const uint8_t *, size_t, solaris_address_t *, size_t *);
#endif
