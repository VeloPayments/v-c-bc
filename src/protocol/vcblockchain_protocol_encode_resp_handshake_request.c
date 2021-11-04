/**
 * \file protocol/vcblockchain_protocol_encode_resp_handshake_request.c
 *
 * \brief Encode a handshake request response into a buffer.
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
 * \brief Encode a handshake request response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded handshake response
 *                                  packet.
 * \param suite                     The crypto suite to use for this response.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param agent_id                  The agent uuid for this response.
 * \param server_public_key         The agent public key.
 * \param server_key_nonce          The agent key nonce.
 * \param server_challenge_nonce    The agent challenge nonce.
 * \param server_cr_hmac            The agent response to the client challenge.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_handshake_request(
    vccrypt_buffer_t* buffer, vccrypt_suite_options_t* suite,
    uint32_t offset, uint32_t status, const vpr_uuid* agent_id,
    const vccrypt_buffer_t* server_public_key,
    const vccrypt_buffer_t* server_key_nonce,
    const vccrypt_buffer_t* server_challenge_nonce,
    const vccrypt_buffer_t* server_cr_hmac)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != agent_id);
    MODEL_ASSERT(NULL != server_public_key);
    MODEL_ASSERT(NULL != server_key_nonce);
    MODEL_ASSERT(NULL != server_challenge_nonce);
    MODEL_ASSERT(NULL != server_cr_hmac);

    const uint32_t net_request_id = htonl(PROTOCOL_REQ_ID_HANDSHAKE_INITIATE);
    const uint32_t net_offset = htonl(offset);
    const uint32_t net_status = htonl(status);
    const uint32_t net_protocol_version = htonl(PROTOCOL_VERSION_0_1_DEMO);
    const uint32_t net_crypto_suite = htonl(suite->suite_id);
    int retval;

    /* verify buffer sizes. */
    if (server_public_key->size != suite->key_cipher_opts.public_key_size
     || server_key_nonce->size != suite->key_cipher_opts.minimum_nonce_size
     || server_challenge_nonce->size != suite->key_cipher_opts.minimum_nonce_size
     || server_cr_hmac->size != suite->mac_short_opts.mac_size)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto done;
    }

    /* | Handshake request response packet.                                 | */
    /* | --------------------------------------------------- | ------------ | */
    /* | DATA                                                | SIZE         | */
    /* | --------------------------------------------------- | ------------ | */
    /* | UNAUTH_PROTOCOL_REQ_ID_HANDSHAKE_INITIATE           |   4 bytes    | */
    /* | status                                              |   4 bytes    | */
    /* | offset                                              |   4 bytes    | */
    /* | record:                                             | 152 bytes    | */
    /* |    protocol_version                                 |   4 bytes    | */
    /* |    crypto_suite                                     |   4 bytes    | */
    /* |    agent_id                                         |  16 bytes    | */
    /* |    server public key                                |  32 bytes    | */
    /* |    server key nonce                                 |  32 bytes    | */
    /* |    server challenge nonce                           |  32 bytes    | */
    /* |    server_cr_hmac                                   |  32 bytes    | */
    /* | --------------------------------------------------- | ------------ | */

    /* compute the size of the response packet. */
    size_t payload_size =
          sizeof(net_request_id)
        + sizeof(net_offset)
        + sizeof(net_status)
        + sizeof(net_protocol_version)
        + sizeof(net_crypto_suite)
        + sizeof(*agent_id)
        + server_public_key->size
        + server_key_nonce->size
        + server_challenge_nonce->size
        + server_cr_hmac->size;

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

    /* write the status to the buffer. */
    memcpy(buf, &net_status, sizeof(net_status));
    buf += sizeof(net_status);

    /* write the offset to the buffer. */
    memcpy(buf, &net_offset, sizeof(net_offset));
    buf += sizeof(net_offset);

    /* write the protocol version to the buffer. */
    memcpy(buf, &net_protocol_version, sizeof(net_protocol_version));
    buf += sizeof(net_protocol_version);

    /* write the crypto suite to the buffer. */
    memcpy(buf, &net_crypto_suite, sizeof(net_crypto_suite));
    buf += sizeof(net_crypto_suite);

    /* write the agent id to the buffer. */
    memcpy(buf, agent_id, sizeof(*agent_id));
    buf += sizeof(*agent_id);

    /* write the server public key to the buffer. */
    memcpy(buf, server_public_key->data, server_public_key->size);
    buf += server_public_key->size;

    /* write the server key nonce to the buffer. */
    memcpy(buf, server_key_nonce->data, server_key_nonce->size);
    buf += server_key_nonce->size;

    /* write the server challenge nonce to the buffer. */
    memcpy(buf, server_challenge_nonce->data, server_challenge_nonce->size);
    buf += server_challenge_nonce->size;

    /* write the server cr hmac to the buffer. */
    memcpy(buf, server_cr_hmac->data, server_cr_hmac->size);
    buf += server_cr_hmac->size;

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;
    goto done;

done:
    return retval;
}
