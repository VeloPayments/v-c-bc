/**
 * \file ssock/ssock_write_data.c
 *
 * \brief Write a data packet to a socket
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/ssock.h>

/**
 * \brief Write a data packet.
 *
 * On success, the data packet value will be written, along with type
 * information and size.
 *
 * \param sock          The \ref ssock socket to which data is written.
 * \param val           The data to write.
 * \param size          The size of the data to write.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing data failed.
 */
int ssock_write_data(ssock* sock, const void* val, uint32_t size)
{
    /* parameter sanity check. */
    MODEL_ASSERT(NULL != sock)
    MODEL_ASSERT(NULL != val);

    /* runtime parameter checks. */
    if (NULL == sock || NULL == val)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    uint8_t typeval = SSOCK_DATA_TYPE_DATA_PACKET;

    /* attempt to write the type to the socket. */
    size_t type_size = sizeof(typeval);
    if (VCBLOCKCHAIN_STATUS_SUCCESS !=
        ssock_write(sock, &typeval, &type_size))
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
    }

    /* attempt to write the length of this data packet to the socket. */
    uint32_t hlen = vchtonl(size);
    size_t hlen_size = sizeof(hlen);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_write(sock, &hlen, &hlen_size))
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
    }

    /* attempt to write the data to the socket. */
    size_t write_size = size;
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_write(sock, val, &write_size))
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
    }

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
