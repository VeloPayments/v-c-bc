/**
 * \file vcblockchain/psock.h
 *
 * \brief psock helpers for vcblockchain.
 *
 * This includes psock functionality that we need for vcblockchain that isn't
 * provided by RCPR, namely, auth data packet I/O.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#pragma once

#include <rcpr/psock.h>
#include <vccrypt/suite.h>

/* C++ compatibility. */
# ifdef   __cplusplus
extern "C" {
# endif /*__cplusplus*/

enum vcblockchain_psock_boxed_type
{
    VCBLOCKCHAIN_PSOCK_BOXED_TYPE_AUTHED_PACKET         = 0x00000030,
};

/**
 * \brief Write an authenticated data packet.
 *
 * On success, the authenticated data packet value will be written, along with
 * type information and size.
 *
 * \param sock          The psock instance to which this packet is written.
 * \param iv            The 64-bit IV to use for this packet.
 * \param val           The payload data to write.
 * \param size          The size of the payload data to write.
 * \param suite         The crypto suite to use for authenticating this packet.
 * \param secret        The shared secret between the peer and host.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int psock_write_authed_data(
    RCPR_SYM(psock)* sock, uint64_t iv, const void* val, uint32_t size,
    vccrypt_suite_options_t* suite, const vccrypt_buffer_t* secret);

/**
 * \brief Read an authenticated data packet.
 *
 * On success, an authenticated data buffer is allocated and read, along with
 * type information and size.  The caller owns this buffer and is responsible
 * for freeing it when it is no longer in use.
 *
 * \param sock          The psock instance from which the packet is read.
 * \param alloc         The allocator to use for this function.
 * \param iv            The 64-bit IV to expect for this packet.
 * \param val           Pointer to the pointer of the raw data buffer.
 * \param size          Pointer to the variable to receive the size of this
 *                      packet.
 * \param suite         The crypto suite to use for authenticating this packet.
 * \param secret        The shared secret between the peer and host.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int psock_read_authed_data(
    RCPR_SYM(psock)* sock, RCPR_SYM(allocator)* alloc, uint64_t iv, void** val,
    uint32_t* size, vccrypt_suite_options_t* suite,
    const vccrypt_buffer_t* secret);

/* C++ compatibility. */
# ifdef   __cplusplus
}
# endif /*__cplusplus*/
