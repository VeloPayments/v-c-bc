/**
 * \file ssock/ssock_read_string.c
 *
 * \brief Read a string packet from a socket.
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/ssock.h>

/**
 * \brief Read a character string from the socket.
 *
 * On success, a character string value is allocated and read, along with type
 * information and size.  The caller owns this character string and is
 * responsible for releasing it to the allocator it when it is no longer in use.
 *
 * \param sock          The \ref ssock socket from which data is read.
 * \param alloc_opts    The allocator options to use for this read.
 * \param val           Pointer to the string pointer to hold the string value
 *                      on success.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_SIZE if the data size is
 *        wrong.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 */
int ssock_read_string(ssock* sock, allocator_options_t* alloc_opts, char** val)
{
    uint32_t type = 0U;
    uint32_t nsize = 0U;
    uint32_t size = 0U;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != val);

    /* runtime parameter checks. */
    if (NULL == sock || NULL == alloc_opts || NULL == val)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* attempt to read the type info. */
    size_t type_size = sizeof(type);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_read(sock, &type, &type_size) || sizeof(type) != type_size)
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
    }

    /* verify that the type is SSOCK_DATA_TYPE_STRING. */
    if (SSOCK_DATA_TYPE_STRING != ntohl(type))
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
    size = vcntohl(nsize);

    /* cap the maximum string size at 10 MB. */
    if (size > (10 * 1024 * 1024))
    {
        return VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_SIZE;
    }

    /* attempt to allocate memory for this string. */
    *val = (char*)allocate(alloc_opts, size + 1);
    if (NULL == *val)
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* attempt to read the string. */
    size_t size_size = size;
    if (VCBLOCKCHAIN_STATUS_SUCCESS != ssock_read(sock, *val, &size_size) || size != size_size)
    {
        release(alloc_opts, *val);
        *val = NULL;
        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
    }

    /* set the asciiz. */
    (*val)[size] = 0;

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
