/**
 * \file ssock/ssock_write_int64.c
 *
 * \brief Write an int64 value packet to a socket
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/ssock.h>

/**
 * \brief Write an int64_t value to the socket.
 *
 * On success, the value is written, along with type information and size.
 *
 * \param sock          The \ref ssock socket to which data is written.
 * \param val           The value to write.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing data failed.
 */
int ssock_write_int64(ssock* sock, int64_t val)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);

    /* runtime parameter checks. */
    if (NULL == sock)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    uint32_t typeval = htonl(SSOCK_DATA_TYPE_INT64);

    /* attempt to write the type to the socket. */
    size_t typeval_size = sizeof(typeval);
    if (VCBLOCKCHAIN_STATUS_SUCCESS !=
            ssock_write(sock, &typeval, &typeval_size) ||
        sizeof(typeval) != typeval_size)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
    }

    /* attempt to write the length of this value to the socket. */
    uint32_t hlen = vchtonl(sizeof(val));
    size_t hlen_size = sizeof(hlen);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_write(sock, &hlen, &hlen_size) || sizeof(hlen) != hlen_size)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
    }

    /* attempt to write the value to the socket. */
    int64_t oval = htonll(val);
    size_t oval_size = sizeof(oval);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_write(sock, &oval, &oval_size) || sizeof(oval) != oval_size)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
    }

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
