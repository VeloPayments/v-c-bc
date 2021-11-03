/**
 * \file vcblockchain/byteswap.h
 *
 * \brief Byteswap routines.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCBLOCKCHAIN_BYTESWAP_HEADER_GUARD
#define VCBLOCKCHAIN_BYTESWAP_HEADER_GUARD

#include <stdint.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/* ARM */
#if defined(__arm__) || defined(__thumb__)
#define VCBLOCKCHAIN_LITTLE_ENDIAN
#endif
/* ARM64 */
#if defined(__aarch64__)
#define VCBLOCKCHAIN_LITTLE_ENDIAN
#endif
/* x86_64 */
#if defined(__x86_64__) || defined(_M_X64)
#define VCBLOCKCHAIN_LITTLE_ENDIAN
#endif
/* i386 */
#if defined(__i386__) || defined(_M_IX86)
#define VCBLOCKCHAIN_LITTLE_ENDIAN
#endif

#ifndef VCBLOCKCHAIN_VCBSWAP_32_IMPL
/**
 * \brief Swap the endian representation of a given 32-bit value.
 *
 * \param val       The value to swap.
 *
 * \returns the swapped value.
 */
inline int32_t vcbswap_32(int32_t val)
{
    uint32_t v = (uint32_t)val;

    return
        ((v & 0xFF000000) >> 24)
      | ((v & 0x00FF0000) >> 8)
      | ((v & 0x0000FF00) << 8)
      | ((v & 0x000000FF) << 24);
}
#endif /*VCBLOCKCHAIN_VCBSWAP_32_IMPL*/

/**
 * \brief Swap the endian representation of a given 64-bit value.
 *
 * \param val       The value to swap.
 *
 * \returns the swapped value.
 */
int64_t bswap_64(int64_t val);

#if !defined(VCBLOCKCHAIN_VCHTONL_IMPL) && !defined(VCBLOCKCHAIN_VCBSWAP_32_IMPL)
/**
 * \brief Perform a host to network byte order swap operation.
 *
 * \param val       The value to swap.
 *
 * \returns the swapped value.
 */
inline int32_t vchtonl(int32_t val)
{
#ifdef VCBLOCKCHAIN_LITTLE_ENDIAN
    return vcbswap_32(val);
#else
    return val;
#endif
}
#endif /*VCBLOCKCHAIN_VCHTONL_IMPL*/

#if !defined(VCBLOCKCHAIN_VCNTOHL_IMPL) && !defined(VCBLOCKCHAIN_VCBSWAP_32_IMPL)
/**
 * \brief Perform a network to host byte order swap operation.
 *
 * \param val       The value to swap.
 *
 * \returns the swapped value.
 */
inline int32_t vcntohl(int32_t val)
{
#ifdef VCBLOCKCHAIN_LITTLE_ENDIAN
    return vcbswap_32(val);
#else
    return val;
#endif
}
#endif /*VCBLOCKCHAIN_VCNTOHL_IMPL*/

/**
 * \brief Perform a host to network byte order swap operation.
 *
 * \param val       The value to swap.
 *
 * \returns the swapped value.
 */
int64_t htonll(int64_t val);

/**
 * \brief Perform a network to host byte order swap operation.
 *
 * \param val       The value to swap.
 *
 * \returns the swapped value.
 */
int64_t ntohll(int64_t val);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCBLOCKCHAIN_BYTESWAP_HEADER_GUARD*/
