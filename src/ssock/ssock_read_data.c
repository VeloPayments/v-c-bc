/**
 * \file ssock/ssock_read_data.c
 *
 * \brief Read a data packet from a socket.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/ssock.h>

/**
 * \brief Read a data packet from the socket.
 *
 * On success, a data buffer is allocated and read, along with type
 * information and size.  The caller owns this buffer and is responsible for
 * releasing it to the allocator when it is no longer in use.
 *
 * \param sock          The \ref ssock socket from which data is read.
 * \param alloc_opts    The allocator options to use for this read.
 * \param val           Pointer to the pointer of the data buffer.
 * \param size          Pointer to the variable to receive the size of this
 *                      packet.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 */
int ssock_read_data(
    ssock* sock, allocator_options_t* alloc_opts, void** val, uint32_t* size)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != val);
    MODEL_ASSERT(NULL != size);

    /* runtime parameter checks. */
    if (NULL == sock || NULL == alloc_opts || NULL == val || NULL == size)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    uint8_t type = 0U;
    uint32_t nsize = 0U;

    /* attempt to read the type info. */
    size_t type_size = sizeof(type);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_read(sock, &type, &type_size) || sizeof(type) != type_size)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
    }

    /* verify that the type is IPC_DATA_TYPE_DATA_PACKET. */
    if (SSOCK_DATA_TYPE_DATA_PACKET != type)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE;
    }

    /* attempt to read the size. */
    size_t nsize_size = sizeof(nsize);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_read(sock, &nsize, &nsize_size) || sizeof(nsize) != nsize_size)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
    }

    /* convert the size to host byte order. */
    *size = vcntohl(nsize);

    /* attempt to allocate memory for this data. */
    *val = allocate(alloc_opts, *size);
    if (NULL == *val)
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* attempt to read the data. */
    size_t read_size = *size;
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_read(sock, *val, &read_size) || *size != read_size)
    {
        release(alloc_opts, *val);
        *val = NULL;
        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
    }

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
