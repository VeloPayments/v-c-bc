/**
 * \file test/dummy_psock.h
 *
 * Dummy psock implementation, used for testing.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#pragma once

#ifndef __cplusplus
#error This is a C++ only header.
#endif /*__cplusplus*/

#include <functional>
#include <rcpr/psock.h>
#include <vector>

/**
 * \brief Create a dummy psock instance for testing.
 * 
 * \param sock      Pointer to the pointer to receive the socket instance.
 * \param a         Allocator to use for this operation.
 * \param onread    Callback for reads.
 * \param onwrite   Callback for writes.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int dummy_psock_create(
    RCPR_SYM(psock)** sock, RCPR_SYM(allocator)* a,
    std::function<int(RCPR_SYM(psock)*, void*, size_t*)> onread,
    std::function<int(RCPR_SYM(psock)*, const void*, size_t*)> onwrite);

/**
 * \brief Helper structure for checking write parameters from the dummy sock.
 */
struct psock_write_params
{
    /**
     * \brief Constructor for \ref ssock_write_params.
     */
    psock_write_params(RCPR_SYM(psock)* s, const void* b, size_t sz);

    RCPR_SYM(psock)* sock;
    std::vector<uint8_t> buf;
};
