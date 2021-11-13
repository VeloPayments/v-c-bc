/**
 * \file protocol/vcblockchain_protocol_encode_resp_block_next_id_get.c
 *
 * \brief Encode a block next id get response into a buffer.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode a block next id get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param next_block_id             The next block id.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_block_next_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* next_block_id)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != next_block_id);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts || NULL == next_block_id)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* create the buffer. */
    size_t resp_size = 3 * sizeof(uint32_t) + sizeof(vpr_uuid);
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, resp_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* populate the integer values. */
    uint32_t* uarr = (uint32_t*)buffer->data;
    uarr[0] = htonl(PROTOCOL_REQ_ID_BLOCK_ID_GET_NEXT);
    uarr[1] = htonl(status);
    uarr[2] = htonl(offset);
    memcpy(&(uarr[3]), next_block_id, sizeof(vpr_uuid));

    /* success. */
    /* On success, the caller owns the buffer and must dispose it. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
