/**
 * \file protocol/vcblockchain_protocol_encode_req_handshake_request.c
 *
 * \brief Encode a handshake request into a buffer.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <string.h>

/**
 * \brief Encode a handshake request using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded handshake packet.
 * \param suite                     The crypto suite to use for this request.
 * \param offset                    The offset for this request.
 * \param client_id                 The client uuid for this request.
 * \param client_key_nonce          The client key nonce for this request.
 * \param client_challenge_nonce    The client challenge nonce for this request.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_handshake_request(
    vccrypt_buffer_t* buffer, vccrypt_suite_options_t* suite,
    uint32_t offset, const vpr_uuid* client_id,
    const vccrypt_buffer_t* client_key_nonce,
    const vccrypt_buffer_t* client_challenge_nonce)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != client_id);
    MODEL_ASSERT(NULL != client_key_nonce);
    MODEL_ASSERT(NULL != client_challenge_nonce);

    const uint32_t net_request_id = htonl(PROTOCOL_REQ_ID_HANDSHAKE_INITIATE);
    const uint32_t net_offset = htonl(offset);
    const uint32_t net_protocol_version = htonl(PROTOCOL_VERSION_0_1_DEMO);
    const uint32_t net_crypto_suite = htonl(suite->suite_id);
    int retval;

    /* verify the nonce sizes. */
    if (client_key_nonce->size != suite->key_cipher_opts.minimum_nonce_size
     || client_challenge_nonce->size != suite->key_cipher_opts.minimum_nonce_size)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto done;
    }

    /* | Handshake request packet.                                          | */
    /* | --------------------------------------------------- | ------------ | */
    /* | DATA                                                | SIZE         | */
    /* | --------------------------------------------------- | ------------ | */
    /* | PROTOCOL_REQ_ID_HANDSHAKE_INITIATE                  |  4 bytes     | */
    /* | offset                                              |  4 bytes     | */
    /* | record:                                             | 88 bytes     | */
    /* |    protocol_version                                 |  4 bytes     | */
    /* |    crypto_suite                                     |  4 bytes     | */
    /* |    client_id                                        | 16 bytes     | */
    /* |    client key nonce                                 | 32 bytes     | */
    /* |    client challenge nonce                           | 32 bytes     | */
    /* | --------------------------------------------------- | ------------ | */

    /* compute the size of the request packet. */
    size_t payload_size =
          sizeof(net_request_id)
        + sizeof(net_offset)
        + sizeof(net_protocol_version)
        + sizeof(net_crypto_suite)
        + sizeof(*client_id)
        + client_key_nonce->size
        + client_challenge_nonce->size;

    /* create output buffer. */
    retval = vccrypt_buffer_init(buffer, suite->alloc_opts, payload_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* write the request to the buffer. */
    uint8_t* buf = (uint8_t*)buffer->data;
    memcpy(buf, &net_request_id, sizeof(net_request_id));
    buf += sizeof(net_request_id);

    /* write the offset to the buffer. */
    memcpy(buf, &net_offset, sizeof(net_offset));
    buf += sizeof(net_offset);

    /* write the protocol version to the buffer. */
    memcpy(buf, &net_protocol_version, sizeof(net_protocol_version));
    buf += sizeof(net_protocol_version);

    /* write the crypto suite id to the buffer. */
    memcpy(buf, &net_crypto_suite, sizeof(net_crypto_suite));
    buf += sizeof(net_crypto_suite);

    /* write the entity id to the buffer. */
    memcpy(buf, client_id, sizeof(*client_id));
    buf += sizeof(*client_id);

    /* write the client key nonce to the buffer. */
    memcpy(buf, client_key_nonce->data, client_key_nonce->size);
    buf += client_key_nonce->size;

    /* write the client challenge nonce to the buffer. */
    memcpy(buf, client_challenge_nonce->data, client_challenge_nonce->size);
    buf += client_challenge_nonce->size;

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;
    goto done;

done:
    return retval;
}
