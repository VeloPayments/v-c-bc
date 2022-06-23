/**
 * \file
 * protocol/vcblockchain_protocol_encode_resp_generic.c
 *
 * \brief Generic response encoder for the protocol.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <string.h>
#include <vcblockchain/protocol/serialization.h>
#include <vcblockchain/error_codes.h>

/**
 * \brief Encode a generic response for the protocol.
 *
 * \param buffer            An uninitialized buffer to hold the response on
 *                          success.
 * \param alloc_opts        The allocator options to use for this operation.
 * \param request_id        The request id originating this response.
 * \param offset            The client offset for this response.
 * \param status_code       The status code for this response.
 * \param payload           The payload buffer for this response, or NULL for no
 *                          payload.
 * \param payload_size      The size of this payload.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_generic(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t request_id, uint32_t offset, uint32_t status_code,
    const void* payload, size_t payload_size)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != payload);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* calculate the header size. */
    size_t resp_size = 3 * sizeof(uint32_t);

    /* maybe add the payload size. */
    if (NULL != payload)
    {
        resp_size += payload_size;
    }

    /* create the buffer. */
    if (VCCRYPT_STATUS_SUCCESS
        != vccrypt_buffer_init(buffer, alloc_opts, resp_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* populate the header values. */
    uint32_t* uarr = (uint32_t*)buffer->data;
    uarr[0] = htonl(request_id);
    uarr[1] = htonl(status_code);
    uarr[2] = htonl(offset);

    /* maybe populate the payload. */
    if (NULL != payload)
    {
        memcpy(uarr + 3, payload, payload_size);
    }

    /* success. */
    /* On success, the caller owns the buffer and must dispose it. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
