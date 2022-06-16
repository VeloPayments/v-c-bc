/**
 * \file
 * protocol/vcblockchain_protocol_decode_resp_assert_latest_block_id_cancel.c
 *
 * \brief Decode a latest block id assertion cancel response into a struct.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_resp_assert_latest_block_id_cancel(void* disp);

/**
 * \brief Decode a latest block id assertion cancel response.
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
int vcblockchain_protocol_decode_resp_assert_latest_block_id_cancel(
    protocol_resp_assert_latest_block_id_cancel* resp, const void* payload,
    size_t payload_size)
{
    /* parameter sanity check. */
    MODEL_ASSERT(NULL != resp);
    MODEL_ASSERT(NULL != payload);

    /* runtime parameter checks. */
    if (NULL == resp || NULL == payload)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* payload size check. */
    const size_t resp_size = 3 * sizeof(uint32_t);
    if (resp_size != payload_size)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* initialize the response structure. */
    memset(resp, 0, sizeof(*resp));
    resp->hdr.dispose = &dispose_protocol_resp_assert_latest_block_id_cancel;
    const uint32_t* parr = (const uint32_t*)payload;
    resp->request_id = ntohl(parr[0]);
    resp->status = ntohl(parr[1]);
    resp->offset = ntohl(parr[2]);

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of a decoded response structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_resp_assert_latest_block_id_cancel(void* disp)
{
    protocol_resp_assert_latest_block_id_cancel* resp =
        (protocol_resp_assert_latest_block_id_cancel*)disp;

    memset(resp, 0, sizeof(protocol_resp_assert_latest_block_id_cancel));
}
