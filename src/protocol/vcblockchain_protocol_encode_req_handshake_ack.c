/**
 * \file protocol/vcblockchain_protocol_encode_req_handshake_ack.c
 *
 * \brief Encode a handshake acknowledge request into a buffer.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode a handshake acknowledge request using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded handshake ack packet.
 * \param suite                     The crypto suite to use for this request.
 * \param digest                    Pointer to buffer holding the mac digest.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_handshake_ack(
    vccrypt_buffer_t* buffer, vccrypt_suite_options_t* suite,
    const vccrypt_buffer_t* digest)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != digest);

    /* create the output buffer, based on the size of the input buffer. */
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, suite->alloc_opts, digest->size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* copy the mac bytes to the buffer. */
    MODEL_ASSERT(buffer->size == digest->size);
    memcpy(buffer->data, digest->data, digest->size);

    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
