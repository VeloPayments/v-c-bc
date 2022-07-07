/**
 * \file
 * protocol/vcblockchain_protocol_decode_req_extended_api.c
 *
 * \brief Decode an extended API request into a struct.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_req_extended_api(void* disp);

/**
 * \brief Decode an extended API request.
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
int vcblockchain_protocol_decode_req_extended_api(
    protocol_req_extended_api* req, allocator_options_t* alloc_opts,
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
        2 * sizeof(uint32_t)
      + 2 * 16;
    if (payload_size < expected_payload_size)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* initialize the request buffer. */
    memset(req, 0, sizeof(*req));
    req->hdr.dispose = &dispose_protocol_req_extended_api;

    /* set the request id and offset. */
    const uint32_t* u32arr = (const uint32_t*)payload;
    req->request_id = ntohl(u32arr[0]);
    req->offset = ntohl(u32arr[1]);

    /* copy the UUIDs. */
    const uint8_t* u8arr = (const uint8_t*)(u32arr + 2);
    memcpy(&req->entity_id, u8arr, sizeof(req->entity_id));
    u8arr += sizeof(req->entity_id);
    memcpy(&req->verb_id, u8arr, sizeof(req->verb_id));
    u8arr += sizeof(req->verb_id);

    /* compute the request body size. */
    const size_t request_body_size = payload_size - expected_payload_size;

    /* create the request body buffer. */
    if (VCCRYPT_STATUS_SUCCESS
        != vccrypt_buffer_init(
                &req->request_body, alloc_opts, request_body_size))
    {
        memset(req, 0, sizeof(*req));
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* copy the request body. */
    memcpy(req->request_body.data, u8arr, request_body_size);

    /* success. */
    /* req is owned by the caller. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of a decoded request structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_req_extended_api(void* disp)
{
    protocol_req_extended_api* req =
        (protocol_req_extended_api*)disp;

    /* clean up the request body if set. */
    if (NULL != req->request_body.data)
    {
        dispose((disposable_t*)&req->request_body);
    }

    /* clear out the structure. */
    memset(req, 0, sizeof(protocol_req_extended_api));
}
