/**
 * \file protocol/vcblockchain_protocol_encode_req_latest_block_id_get.c
 *
 * \brief Encode a latest block id get request into a buffer.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode a latest block id get request.
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
int vcblockchain_protocol_encode_req_latest_block_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* create the buffer for holding the request. */
    size_t req_size = 2 * sizeof(uint32_t);
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, req_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* populate the request. */
    uint32_t* barr = (uint32_t*)buffer->data;
    barr[0] = htonl(PROTOCOL_REQ_ID_LATEST_BLOCK_ID_GET);
    barr[1] = htonl(offset);

    /* success; the caller owns buffer on success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
