/**
 * \file byteswap/vchtonl.c
 *
 * \brief Perform a network to host byte order swap operation.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#define VCBLOCKCHAIN_VCNTOHL_IMPL

#include <vcblockchain/byteswap.h>

/**
 * \brief Perform a network to host byte order swap operation.
 *
 * \param val       The value to swap.
 *
 * \returns the swapped value.
 */
int32_t vcntohl(int32_t val)
{
#ifdef VCBLOCKCHAIN_LITTLE_ENDIAN
    return vcbswap_32(val);
#else
    return val;
#endif
}
