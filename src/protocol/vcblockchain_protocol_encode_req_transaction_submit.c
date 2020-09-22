/**
 * \file protocol/vcblockchain_protocol_encode_req_transaction_submit.c
 *
 * \brief Encode a transaction submit request into a buffer.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode a transaction submit request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param txn_id                    The id of this transaction.
 * \param artifact_id               The artifact id of this transaction.
 * \param cert                      Pointer to the certificate data for this
 *                                  transaction.
 * \param cert_size                 The size of this certificate in bytes.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_transaction_submit(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* txn_id, const vpr_uuid* artifact_id,
    const void* cert, size_t cert_size)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != txn_id);
    MODEL_ASSERT(NULL != artifact_id);
    MODEL_ASSERT(NULL != cert);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts || NULL == txn_id
     || NULL == artifact_id || NULL == cert)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* cumpute the buffer size. */
    size_t buffer_size =
          2 * sizeof(uint32_t) /* request_id and offset */
        + sizeof(*txn_id)
        + sizeof(*artifact_id)
        + cert_size;

    /* initialize the buffer. */
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, buffer_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* write the request id and offset. */
    uint32_t* u32arr = (uint32_t*)buffer->data;
    u32arr[0] = htonl(PROTOCOL_REQ_ID_TRANSACTION_SUBMIT);
    u32arr[1] = htonl(offset);

    /* copy the ids. */
    uint8_t* barr = (uint8_t*)(u32arr + 2);
    memcpy(barr, txn_id, sizeof(*txn_id));
    memcpy(barr + 16, artifact_id, sizeof(*artifact_id));

    /* copy the certificate. */
    memcpy(barr + 32, cert, cert_size);

    /* success. */
    /* buffer is owned by the caller on success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
