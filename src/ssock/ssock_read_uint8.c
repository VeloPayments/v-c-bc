/**
 * \file ssock/ssock_read_uint8.c
 *
 * \brief Read a uint8 value packet from a socket.
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/ssock.h>

/**
 * \brief Read a uint8_t value from the socket.
 *
 * On success, the value is read, along with type information and size.
 *
 * \param sock          The \ref ssock socket from which data is read.
 * \param val           Pointer to hold the value.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_SIZE if the data size
 *        read from the socket was unexpected.
 */
int ssock_read_uint8(ssock* sock, uint8_t* val)
{
    uint32_t type = 0U;
    uint8_t nval = 0U;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != val);

    /* runtime parameter checks. */
    if (NULL == sock || NULL == val)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* attempt to read the type info. */
    size_t type_size = sizeof(type);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_read(sock, &type, &type_size) || sizeof(type) != type_size)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
    }

    /* verify that the type is SSOCK_DATA_TYPE_UINT8. */
    if (SSOCK_DATA_TYPE_UINT8 != ntohl(type))
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE;
    }

    /* attempt to read the value. */
    size_t val_size = sizeof(uint8_t);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_read(sock, &nval, &val_size) || sizeof(uint8_t) != val_size)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
    }

    /* convert this value to host byte order. */
    *val = nval;

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
