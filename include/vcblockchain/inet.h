/**
 * \file vcblockchain/inet.h
 *
 * \brief Network related functions for vcblockchain.
 *
 * \copyright 2023 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCBLOCKCHAIN_INET_HEADER_GUARD
#define VCBLOCKCHAIN_INET_HEADER_GUARD

#include <rcpr/allocator.h>
#include <sys/socket.h>
#include <sys/types.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief Convert an address to a canonial IP form, either as an IPv4 or an IPv6
 * address. 
 *
 * The address can be a fully qualified domain name, a local domain name, or an
 * IP address.
 *
 * \param canonical_addr                Pointer to the character pointer to
 *                                      receive the canonical address on
 *                                      success. This address is allocated with
 *                                      the provided allocator and must be
 *                                      reclaimed when no longer needed.
 * \param alloc                         The allocator to use for this operation.
 * \param query_addr                    The address to query.
 * \param domain                        The domain for this address. It must be
 *                                      AF_INET or AF_INET6.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status FN_DECL_MUST_CHECK vcblockchain_inet_resolve_address(
    char** canonical_addr, RCPR_SYM(allocator)* alloc, const char* query_addr,
    int domain);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCBLOCKCHAIN_INET_HEADER_GUARD*/
