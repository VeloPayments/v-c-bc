/**
 * \file protocol/vcblockchain_protocol_encode_resp_txn_get.c
 *
 * \brief Encode a txn get response into a buffer.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode a transaction get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param txn_id                    The transaction id.
 * \param prev_txn_id               The previous transaction id.
 * \param next_txn_id               The next transaction id.
 * \param artifact_id               The artifact id for this transaction.
 * \param block_id                  The block id for this transaction.
 * \param ser_txn_cert_size         The serialized transaction cert size.
 * \param txn_cert                  Pointer to the start of the transaction
 *                                  certificate.
 * \param txn_cert_size             The transaction cert size.
 * \param txn_state                 The transaction state.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_txn_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* txn_id,
    const vpr_uuid* prev_txn_id, const vpr_uuid* next_txn_id,
    const vpr_uuid* artifact_id, const vpr_uuid* block_id,
    uint64_t ser_txn_cert_size, const void* txn_cert, size_t txn_cert_size,
    uint32_t txn_state)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != txn_id);
    MODEL_ASSERT(NULL != prev_txn_id);
    MODEL_ASSERT(NULL != next_txn_id);
    MODEL_ASSERT(NULL != artifact_id);
    MODEL_ASSERT(NULL != block_id);
    MODEL_ASSERT(NULL != txn_cert);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts || NULL == txn_id
     || NULL == prev_txn_id || NULL == next_txn_id || NULL == artifact_id
     || NULL == block_id || NULL == txn_cert)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* compute the buffer size. */
    size_t resp_size =
          3 * sizeof(uint32_t) /* request_id, offset, and status. */
        + sizeof(*txn_id)
        + sizeof(*prev_txn_id)
        + sizeof(*next_txn_id)
        + sizeof(*artifact_id)
        + sizeof(*block_id)
        + sizeof(ser_txn_cert_size)
        + sizeof(txn_state)
        + txn_cert_size;

    /* create the buffer. */
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, resp_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* populate the integer values. */
    uint32_t* uarr = (uint32_t*)buffer->data;
    uarr[0] = htonl(PROTOCOL_REQ_ID_TRANSACTION_BY_ID_GET);
    uarr[1] = htonl(status);
    uarr[2] = htonl(offset);

    /* populate the uuid values. */
    uint8_t* barr = (uint8_t*)(uarr + 3);
    memcpy(barr,        txn_id, 16);
    memcpy(barr + 16,   prev_txn_id, 16);
    memcpy(barr + 32,   next_txn_id, 16);
    memcpy(barr + 48,   artifact_id, 16);
    memcpy(barr + 64,   block_id, 16);

    /* populate the serialized txn cert size. */
    uint64_t net_ser_txn_cert_size = htonll(ser_txn_cert_size);
    memcpy(barr + 80,   &net_ser_txn_cert_size, 8);

    /* populate the transaction state. */
    uint32_t net_txn_state = htonl(txn_state);
    memcpy(barr + 88,   &net_txn_state, 4);

    /* populate the transaction certificate. */
    memcpy(barr + 92, txn_cert, txn_cert_size);

    /* success. */
    /* On success, the caller owns the buffer and must dispose it. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
