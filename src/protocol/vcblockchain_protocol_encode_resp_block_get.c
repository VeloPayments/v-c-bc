/**
 * \file protocol/vcblockchain_protocol_encode_resp_block_get.c
 *
 * \brief Encode a block get response into a buffer.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode a block get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param block_id                  The block id.
 * \param prev_block_id             The previous block id.
 * \param next_block_id             The next block id.
 * \param first_txn_id              The first transaction id in the block.
 * \param block_height              The block height.
 * \param ser_block_cert_size       The serialized block cert size.
 * \param block_cert                Pointer to the start of the block
 *                                  certificate.
 * \param block_cert_size           The block cert size.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_block_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* block_id,
    const vpr_uuid* prev_block_id, const vpr_uuid* next_block_id,
    const vpr_uuid* first_txn_id, uint64_t block_height,
    uint64_t ser_block_cert_size, const void* block_cert,
    size_t block_cert_size)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != block_id);
    MODEL_ASSERT(NULL != prev_block_id);
    MODEL_ASSERT(NULL != next_block_id);
    MODEL_ASSERT(NULL != first_txn_id);
    MODEL_ASSERT(NULL != block_cert);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts || NULL == block_id
     || NULL == prev_block_id || NULL == next_block_id || NULL == first_txn_id
     || NULL == block_cert)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* compute the buffer size. */
    size_t resp_size =
          3 * sizeof(uint32_t) /* request_id, offset, and status. */
        + sizeof(*block_id)
        + sizeof(*prev_block_id)
        + sizeof(*next_block_id)
        + sizeof(*first_txn_id)
        + sizeof(block_height)
        + sizeof(ser_block_cert_size)
        + block_cert_size;

    /* create the buffer. */
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, resp_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* populate the integer values. */
    uint32_t* uarr = (uint32_t*)buffer->data;
    uarr[0] = htonl(PROTOCOL_REQ_ID_BLOCK_BY_ID_GET);
    uarr[1] = htonl(status);
    uarr[2] = htonl(offset);

    /* populate the uuid values. */
    uint8_t* barr = (uint8_t*)(uarr + 3);
    memcpy(barr,        block_id, 16);
    memcpy(barr + 16,   prev_block_id, 16);
    memcpy(barr + 32,   next_block_id, 16);
    memcpy(barr + 48,   first_txn_id, 16);

    /* populate the block height. */
    uint64_t net_block_height = htonll(block_height);
    memcpy(barr + 64,   &net_block_height, 8);

    /* populate the serialized block cert size. */
    uint64_t net_ser_block_size = htonll(ser_block_cert_size);
    memcpy(barr + 72,   &net_ser_block_size, 8);

    /* populate the block certificate. */
    memcpy(barr + 80, block_cert, block_cert_size);

    /* success. */
    /* On success, the caller owns the buffer and must dispose it. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
