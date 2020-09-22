/**
 * \file protocol/vcblockchain_protocol_decode_resp_transaction_submit.c
 *
 * \brief Decode a transaction submit response into a struct.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_resp_transaction_submit(void* disp);

/**
 * \brief Decode a transaction submit response.
 *
 * \param resp                      The decoded response buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p resp structure is initialized with the decoded values.
 * The caller owns this structure and must \ref dispose() it when it is no
 * longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_resp_transaction_submit(
    protocol_resp_transaction_submit* resp,
    const void* payload, size_t payload_size)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != resp);
    MODEL_ASSERT(NULL != payload);

    /* runtime parameter checks. */
    if (NULL == resp || NULL == payload)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* verify that the payload size is correct. */
    const size_t expected_payload_size = 3 * sizeof(uint32_t);
    if (payload_size != expected_payload_size)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* initialize the response structure. */
    memset(resp, 0, sizeof(*resp));
    resp->hdr.dispose = &dispose_protocol_resp_transaction_submit;
    const uint32_t* u32arr = (const uint32_t*)payload;
    resp->request_id = ntohl(u32arr[0]);
    resp->offset = ntohl(u32arr[1]);
    resp->status = ntohl(u32arr[2]);

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of a decoded response structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_resp_transaction_submit(void* disp)
{
    protocol_resp_transaction_submit* resp =
        (protocol_resp_transaction_submit*)disp;

    memset(resp, 0, sizeof(protocol_resp_transaction_submit));
}
