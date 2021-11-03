/**
 * \file byteswap/vcbswap_32.c
 *
 * \brief Swap the endian representation of a given 32-bit value.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#define VCBLOCKCHAIN_VCBSWAP_32_IMPL

#include <vcblockchain/byteswap.h>

/**
 * \brief Swap the endian representation of a given 32-bit value.
 *
 * \param val       The value to swap.
 *
 * \returns the swapped value.
 */
int32_t vcbswap_32(int32_t val)
{
    uint32_t v = (uint32_t)val;

    return
        ((v & 0xFF000000) >> 24)
      | ((v & 0x00FF0000) >> 8)
      | ((v & 0x0000FF00) << 8)
      | ((v & 0x000000FF) << 24);
}
