/**
 * \file protocol/vcblockchain_protocol_decode_req_txn_get.c
 *
 * \brief Decode a transaction get request into a struct.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_req_txn_get(void* disp);

/**
 * \brief Decode a transaction get request.
 *
 * \param req                       The decoded request buffer.
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
int vcblockchain_protocol_decode_req_txn_get(
    protocol_req_txn_get* req, const void* payload, size_t payload_size)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != req);
    MODEL_ASSERT(NULL != payload);

    /* runtime parameter checks. */
    if (NULL == req || NULL == payload)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* verify that the payload size is correct. */
    const size_t expected_payload_size = 2 * sizeof(uint32_t) + 16;
    if (expected_payload_size != payload_size)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* initialize the request buffer. */
    memset(req, 0, sizeof(*req));
    req->hdr.dispose = &dispose_protocol_req_txn_get;

    /* set the request id and offset. */
    const uint32_t* u32arr = (const uint32_t*)payload;
    req->request_id = ntohl(u32arr[0]);
    req->offset = ntohl(u32arr[1]);

    /* copy the txn id. */
    const uint8_t* barr = (const uint8_t*)(u32arr + 2);
    memcpy(&req->txn_id, barr, 16);

    /* success. */
    /* req is owned by the caller. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of a decoded request structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_req_txn_get(void* disp)
{
    protocol_req_txn_get* req =
        (protocol_req_txn_get*)disp;

    memset(req, 0, sizeof(protocol_req_txn_get));
}
