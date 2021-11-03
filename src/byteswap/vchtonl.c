/**
 * \file byteswap/vchtonl.c
 *
 * \brief Perform a host to network byte order swap operation.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#define VCBLOCKCHAIN_VCHTONL_IMPL

#include <vcblockchain/byteswap.h>

/**
 * \brief Perform a host to network byte order swap operation.
 *
 * \param val       The value to swap.
 *
 * \returns the swapped value.
 */
int32_t vchtonl(int32_t val)
{
#ifdef VCBLOCKCHAIN_LITTLE_ENDIAN
    return vcbswap_32(val);
#else
    return val;
#endif
}
