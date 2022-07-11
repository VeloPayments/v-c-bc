/**
 * \file protocol/vcblockchain_protocol_decode_req_extended_api_response.c
 *
 * \brief Decode an extended API response request into a struct.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_req_extended_api_response(void* disp);

/**
 * \brief Decode an extended API request to send a client response.
 *
 * \param req                       The decoded request buffer.
 * \param alloc_opts                The allocator to use for this operation.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() of it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_extended_api_response(
    protocol_req_extended_api_response* req, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != req);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != payload);

    /* runtime parameter checks. */
    if (NULL == req || NULL == alloc_opts || NULL == payload)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* verify that the payload size is correct. */
    const size_t expected_payload_size =
        sizeof(uint32_t)
      + sizeof(uint64_t)
      + sizeof(uint32_t);
    if (payload_size < expected_payload_size)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* initialize the request buffer. */
    memset(req, 0, sizeof(*req));
    req->hdr.dispose = &dispose_protocol_req_extended_api_response;

    /* make working with the payload more convenient. */
    const uint8_t* barr = (const uint8_t*)payload;

    /* copy the request id. */
    uint32_t net_request_id;
    memcpy(&net_request_id, barr, sizeof(net_request_id));
    barr += sizeof(net_request_id);
    req->request_id = ntohl(net_request_id);

    /* copy the offset. */
    uint64_t net_offset;
    memcpy(&net_offset, barr, sizeof(net_offset));
    barr += sizeof(net_offset);
    req->offset = ntohll(net_offset);

    /* copy the status. */
    uint32_t net_status;
    memcpy(&net_status, barr, sizeof(net_status));
    barr += sizeof(net_status);
    req->status = ntohl(net_status);

    /* compute the response body size. */
    const size_t response_body_size = payload_size - expected_payload_size;

    /* create the request body buffer. */
    if (VCCRYPT_STATUS_SUCCESS
        != vccrypt_buffer_init(
                &req->response_body, alloc_opts, response_body_size))
    {
        memset(req, 0, sizeof(*req));
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* copy the response body. */
    memcpy(req->response_body.data, barr, req->response_body.size);
    barr += req->response_body.size;

    /* success. */
    /* req is owned by the caller. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of a decoded request structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_req_extended_api_response(void* disp)
{
    protocol_req_extended_api_response* req =
        (protocol_req_extended_api_response*)disp;

    /* clean up the response body if set. */
    if (NULL != req->response_body.data)
    {
        dispose((disposable_t*)&req->response_body);
    }

    /* clear out the structure. */
    memset(req, 0, sizeof(protocol_req_extended_api_response));
}
