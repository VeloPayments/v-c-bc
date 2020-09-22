/**
 * \file protocol/vcblockchain_protocol_decode_req_transaction_submit.c
 *
 * \brief Decode a transaction submit request into a struct.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_req_transaction_submit(void* disp);

/**
 * \brief Decode a transaction submit request.
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
int vcblockchain_protocol_decode_req_transaction_submit(
    protocol_req_transaction_submit* req, allocator_options_t* alloc_opts,
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

    /* verify that the payload is at least large enough to hold the header. */
    const size_t minimum_payload_size = 2 * sizeof(uint32_t) + 2 * 16;
    if (payload_size < minimum_payload_size)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* initialize the request buffer. */
    memset(req, 0, sizeof(*req));
    req->hdr.dispose = &dispose_protocol_req_transaction_submit;

    /* initialize the transaction cert. */
    size_t cert_size = payload_size - minimum_payload_size;
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(&req->cert, alloc_opts, cert_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* set the request_id and offset. */
    const uint32_t* u32arr = (const uint32_t*)payload;
    req->request_id = ntohl(u32arr[0]);
    req->offset = ntohl(u32arr[1]);

    /* copy the transaction id and artifact id. */
    const uint8_t* barr = (const uint8_t*)(u32arr + 2);
    memcpy(&req->txn_id,      barr,      16);
    memcpy(&req->artifact_id, barr + 16, 16);

    /* copy the certificate. */
    memcpy(req->cert.data, barr + 32, cert_size);

    /* success. */
    /* req is owned by the caller. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of a decoded request structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_req_transaction_submit(void* disp)
{
    protocol_req_transaction_submit* req =
        (protocol_req_transaction_submit*)disp;

    /* clean up the certificate buffer. */
    dispose((disposable_t*)&req->cert);

    memset(req, 0, sizeof(protocol_req_transaction_submit));
}
