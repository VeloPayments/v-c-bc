/**
 * \file protocol/vcblockchain_protocol_encode_resp_assert_latest_block_id.c
 *
 * \brief Encode a latest block id assertion response.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode a latest block id assertion response.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_assert_latest_block_id(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* create the buffer. */
    size_t resp_size = 3 * sizeof(uint32_t);
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, resp_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* populate the integer values. */
    uint32_t* uarr = (uint32_t*)buffer->data;
    uarr[0] = htonl(PROTOCOL_REQ_ID_ASSERT_LATEST_BLOCK_ID);
    uarr[1] = htonl(status);
    uarr[2] = htonl(offset);

    /* success. */
    /* On success, the caller owns the buffer and must dispose it. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
