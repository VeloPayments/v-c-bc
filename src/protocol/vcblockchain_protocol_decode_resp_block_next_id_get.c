/**
 * \file protocol/vcblockchain_protocol_decode_resp_block_next_id_get.c
 *
 * \brief Decode a block next id get response into a struct.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_resp_block_next_id_get(void* disp);

/**
 * \brief Decode a block next id get response.
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
int vcblockchain_protocol_decode_resp_block_next_id_get(
    protocol_resp_block_next_id_get* resp, const void* payload,
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
    const size_t resp_size = 3 * sizeof(uint32_t) + 16;
    if (resp_size != payload_size)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* initialize the response structure. */
    memset(resp, 0, sizeof(*resp));
    resp->hdr.dispose = &dispose_protocol_resp_block_next_id_get;
    const uint32_t* parr = (const uint32_t*)payload;
    resp->request_id = ntohl(parr[0]);
    resp->status = ntohl(parr[1]);
    resp->offset = ntohl(parr[2]);
    memcpy(&resp->next_block_id, &(parr[3]), sizeof(resp->next_block_id));

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of a decoded response structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_resp_block_next_id_get(void* disp)
{
    protocol_resp_block_next_id_get* resp =
        (protocol_resp_block_next_id_get*)disp;

    memset(resp, 0, sizeof(protocol_resp_block_next_id_get));
}
