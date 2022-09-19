/**
 * \file
 * protocol/vcblockchain_protocol_encode_req_extended_api_response.c
 *
 * \brief Encode an extended API response request.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode an extended API request to send a response to a client.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this operation.
 * \param offset                    The offset to use for this request.
 * \param status                    The status to use for this request.
 * \param response_body             The body of the response to be sent.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request. The caller owns this buffer and must \ref dispose() it when it is no
 * longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_extended_api_response(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint64_t offset,
    uint32_t status, const vccrypt_buffer_t* response_body)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != response_body);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts
     || NULL == response_body)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* compute the buffer size. */
    size_t buffer_size =
        sizeof(uint32_t) /* request_id */
      + sizeof(uint64_t) /* offset */
      + sizeof(uint32_t) /* status */
      + response_body->size;

    /* initialize the buffer. */
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, buffer_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* make working with this buffer more convenient. */
    uint8_t* barr = (uint8_t*)buffer->data;

    /* write the request id. */
    uint32_t net_request_id = htonl(PROTOCOL_REQ_ID_EXTENDED_API_SENDRESP);
    memcpy(barr, &net_request_id, sizeof(net_request_id));
    barr += sizeof(net_request_id);

    /* write the offset. */
    uint64_t net_offset = htonll(offset);
    memcpy(barr, &net_offset, sizeof(net_offset));
    barr += sizeof(net_offset);

    /* write the status. */
    uint32_t net_status = htonl(status);
    memcpy(barr, &net_status, sizeof(net_status));
    barr += sizeof(net_status);

    /* write the response buffer. */
    if (NULL != response_body->data && response_body->size > 0)
    {
        memcpy(barr, response_body->data, response_body->size);
        barr += response_body->size;
    }

    /* success. */
    /* buffer is owned by the caller on success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
