/**
 * \file ssock/ssock_write_string.c
 *
 * \brief Write a string packet to a socket
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/ssock.h>

/**
 * \brief Write a character string to the socket.
 *
 * On success, the character string value is written, along with type
 * information and size.
 *
 * \param sock          The \ref ssock socket to which data is written.
 * \param val           The string to write.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing data failed.
 */
int ssock_write_string(ssock* sock, const char* val)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != val);

    /* runtime parameter checks. */
    if (NULL == sock || NULL == val)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    uint32_t typeval = htonl(SSOCK_DATA_TYPE_STRING);

    /* attempt to write the type to the socket. */
    size_t typeval_size = sizeof(typeval);
    if (VCBLOCKCHAIN_STATUS_SUCCESS !=
            ssock_write(sock, &typeval, &typeval_size) ||
        sizeof(typeval) != typeval_size)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
    }

    /* attempt to write the length of this string to the socket. */
    uint32_t len = strlen(val);
    uint32_t hlen = vchtonl(len);
    size_t hlen_size = sizeof(hlen);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_write(sock, &hlen, &hlen_size) || sizeof(hlen) != hlen_size)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
    }

    /* attempt to write the string to the socket. */
    size_t val_len = len;
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_write(sock, val, &val_len) || len != val_len)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
    }

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
