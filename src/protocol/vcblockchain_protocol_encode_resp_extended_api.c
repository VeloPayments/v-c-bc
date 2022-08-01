/**
 * \file
 * protocol/vcblockchain_protocol_encode_resp_extended_api.c
 *
 * \brief Encode an extended api response.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode an extended API response.
 *
 * \param buffer                    Pointer to an unitialized buffer to receive
 *                                  the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param response_body             The response body for this response.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response. The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_extended_api(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint32_t offset,
    uint32_t status, const vccrypt_buffer_t* response_body)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != response_body);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts || NULL == response_body)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* create the buffer. */
    size_t resp_size = 3 * sizeof(uint32_t) + response_body->size;
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, resp_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* populate the integer values. */
    uint32_t* uarr = (uint32_t*)buffer->data;
    uarr[0] = htonl(PROTOCOL_REQ_ID_EXTENDED_API_SENDRECV);
    uarr[1] = htonl(status);
    uarr[2] = htonl(offset);

    /* copy the response body. */
    memcpy(uarr + 3, response_body->data, response_body->size);

    /* success. */
    /* On success, the caller owns the buffer and must dispose it. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
