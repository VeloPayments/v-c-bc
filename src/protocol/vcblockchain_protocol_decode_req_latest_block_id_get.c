/**
 * \file protocol/vcblockchain_protocol_decode_req_latest_block_id_get.c
 *
 * \brief Decode a latest block id get request into a struct.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_req_latest_block_id_get(void* disp);

/**
 * \brief Decode a latest block id get request.
 *
 * \param req                       The decoded request buffer.
 * \param alloc_opts                The allocator options to use.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The 
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_latest_block_id_get(
    protocol_req_latest_block_id_get* req, allocator_options_t* alloc_opts,
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

    /* payload size check. */
    const size_t req_size = 2 * sizeof(uint32_t);
    if (req_size != payload_size)
    {
        return VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_PAYLOAD_SIZE;
    }

    /* initialize the request structure. */
    memset(req, 0, sizeof(*req));
    req->hdr.dispose = &dispose_protocol_req_latest_block_id_get;
    const uint32_t* parr = (const uint32_t*)payload;
    req->request_id = ntohl(parr[0]);
    req->offset = ntohl(parr[1]);

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of a decoded request structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_req_latest_block_id_get(void* disp)
{
    protocol_req_latest_block_id_get* req =
        (protocol_req_latest_block_id_get*)disp;

    memset(req, 0, sizeof(protocol_req_latest_block_id_get));
}
