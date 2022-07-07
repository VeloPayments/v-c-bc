/**
 * \file
 * protocol/vcblockchain_protocol_decode_resp_extended_api.c
 *
 * \brief Decode an extended API response into a struct.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_resp_extended_api(void* disp);

/**
 * \brief Decode an extended API response.
 *
 * \param resp                      The decoded response buffer.
 * \param alloc_opts                The allocator options to use for this
 *                                  operation.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p resp structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_resp_extended_api(
    protocol_resp_extended_api* resp, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size)
{
    /* parameter sanity check. */
    MODEL_ASSERT(NULL != resp);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != payload);

    /* runtime parameter checks. */
    if (NULL == resp || NULL == alloc_opts || NULL == payload)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* payload size check. */
    const size_t resp_size = 3 * sizeof(uint32_t);
    if (payload_size < resp_size)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* initialize the response structure. */
    memset(resp, 0, sizeof(*resp));
    resp->hdr.dispose = &dispose_protocol_resp_extended_api;
    const uint32_t* parr = (const uint32_t*)payload;
    resp->request_id = ntohl(parr[0]);
    resp->status = ntohl(parr[1]);
    resp->offset = ntohl(parr[2]);

    /* compute the size of the response body. */
    const size_t response_body_size = payload_size - resp_size;

    /* create the response body buffer. */
    if (VCCRYPT_STATUS_SUCCESS
        != vccrypt_buffer_init(
                &resp->response_body, alloc_opts, response_body_size))
    {
        memset(resp, 0, sizeof(*resp));
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* copy the response body data. */
    memcpy(resp->response_body.data, parr + 3, response_body_size);

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of a decoded response structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_resp_extended_api(void* disp)
{
    protocol_resp_extended_api* resp =
        (protocol_resp_extended_api*)disp;

    /* dispose of buffer if set. */
    if (NULL != resp->response_body.data)
    {
        dispose((disposable_t*)&resp->response_body);
    }

    memset(resp, 0, sizeof(protocol_resp_extended_api));
}
