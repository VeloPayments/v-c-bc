/**
 * \file protocol/vcblockchain_protocol_decode_resp_txn_get.c
 *
 * \brief Decode a transaction get response into a struct.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_resp_txn_get(void* disp);

/**
 * \brief Decode a transaction get response.
 *
 * \param resp                      The decoded response buffer.
 * \param alloc_opts                The allocator to use for this response.
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
int vcblockchain_protocol_decode_resp_txn_get(
    protocol_resp_txn_get* resp, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != resp);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != payload);

    /* runtime parameter checks. */
    if (NULL == resp || NULL == alloc_opts || NULL == payload)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* compute the minimum payload size. */
    const size_t minimum_payload_size =
          3 * sizeof(uint32_t) /* request_id, offset, and status. */
        + 5 * 16 /* txn_id, prev_txn_id, next_txn_id, artifact_id, block_id. */
        + 1 * sizeof(uint64_t) /* serialized cert size. */
        + 1 * sizeof(uint32_t); /* serialized transaction state. */

    /* verify that payload_size is at least the minimum. */
    if (payload_size < minimum_payload_size)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* initialize the response structure. */
    memset(resp, 0, sizeof(*resp));
    resp->hdr.dispose = &dispose_protocol_resp_txn_get;

    /* allocate the transaction cert buffer. */
    const size_t cert_size = payload_size - minimum_payload_size;
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(&resp->txn_cert, alloc_opts, cert_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* set the integer values. */
    const uint32_t* uarr = (const uint32_t*)payload;
    resp->request_id = vcntohl(uarr[0]);
    resp->status = vcntohl(uarr[1]);
    resp->offset = vcntohl(uarr[2]);

    /* set the uuid values. */
    const uint8_t* barr = (const uint8_t*)(uarr + 3);
    memcpy(&resp->txn_id,           barr,       16);
    memcpy(&resp->prev_txn_id,      barr + 16,  16);
    memcpy(&resp->next_txn_id,      barr + 32,  16);
    memcpy(&resp->artifact_id,      barr + 48,  16);
    memcpy(&resp->block_id,         barr + 64,  16);

    /* set the uint64_t values. */
    uint64_t net_txn_size;
    memcpy(&net_txn_size, barr + 80, 8);
    resp->txn_size = ntohll(net_txn_size);

    /* set the uint32_t values. */
    uint32_t net_txn_state;
    memcpy(&net_txn_state, barr + 88, 4);
    resp->txn_state = ntohl(net_txn_state);

    /* copy the transaction certificate. */
    memcpy(resp->txn_cert.data, barr + 92, cert_size);

    /* success. */
    /* On success, the caller owns resp. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of a decoded response structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_resp_txn_get(void* disp)
{
    protocol_resp_txn_get* resp = (protocol_resp_txn_get*)disp;

    /* dispose of the block certificate buffer. */
    dispose((disposable_t*)&resp->txn_cert);

    memset(resp, 0, sizeof(protocol_resp_txn_get));
}
