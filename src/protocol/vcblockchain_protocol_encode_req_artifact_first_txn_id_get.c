/**
 * \file protocol/vcblockchain_protocol_encode_req_artifact_first_txn_id_get.c
 *
 * \brief Encode a block next id get request into a buffer.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode an artifact first txn id get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param artifact_id               The id of artifact to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_artifact_first_txn_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* artifact_id)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(prop_valid_vccrypt_buffer(buffer));
    MODEL_ASSERT(prop_valid_allocator(alloc_opts));
    MODEL_ASSERT(NULL != artifact_id);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts || NULL == artifact_id)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* compute the buffer size. */
    size_t buffer_size =
          2 * sizeof(uint32_t) /* request_id and offset */
        + sizeof(*artifact_id);

    /* initialize the buffer. */
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, buffer_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* write the request id and offset. */
    uint32_t* u32arr = (uint32_t*)buffer->data;
    u32arr[0] = htonl(PROTOCOL_REQ_ID_ARTIFACT_FIRST_TXN_BY_ID_GET);
    u32arr[1] = htonl(offset);

    /* copy the block id. */
    uint8_t* barr = (uint8_t*)(u32arr + 2);
    memcpy(barr, artifact_id, sizeof(*artifact_id));

    /* success. */
    /* buffer is owned by the caller on success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
