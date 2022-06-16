/**
 * \file
 * protocol/vcblockchain_protocol_encode_req_assert_latest_block_id_cancel.c
 *
 * \brief Encode a latest block id assertion cancel request.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode a latest block id assertion cancel request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_assert_latest_block_id_cancel(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint32_t offset)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* compute the buffer size. */
    size_t buffer_size = 2 * sizeof(uint32_t); /* request_id and offset */

    /* initialize the buffer. */
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, buffer_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* write the request id and offset. */
    uint32_t* u32arr = (uint32_t*)buffer->data;
    u32arr[0] = htonl(PROTOCOL_REQ_ID_ASSERT_LATEST_BLOCK_ID);
    u32arr[1] = htonl(offset);

    /* success. */
    /* buffer is owned by the caller on success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
