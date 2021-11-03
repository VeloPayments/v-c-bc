/**
 * \file protocol/vcblockchain_protocol_decode_resp_handshake_request.c
 *
 * \brief Decode a handshake request response into a response structure.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <string.h>

/* forward decls. */
static void dispose_protocol_resp_handshake_request(void* disp);

/**
 * \brief Decode a handshake request response using the given parameters.
 *
 * \param resp                      The decoded response buffer.
 * \param suite                     The crypto suite to use for this request.
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
int vcblockchain_protocol_decode_resp_handshake_request(
    protocol_resp_handshake_request* resp, vccrypt_suite_options_t* suite,
    const void* payload, size_t payload_size)
{
    int retval;
    uint32_t net_request_id, net_offset, net_status, net_protocol_version;
    uint32_t net_crypto_suite;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != resp);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != payload);

    /* compute failure payload size. */
    size_t expected_fail_payload_size =
          sizeof(net_request_id)
        + sizeof(net_offset)
        + sizeof(net_status);

    /* compute the expected full payload size. */
    size_t expected_full_payload_size =
          sizeof(net_request_id)
        + sizeof(net_offset)
        + sizeof(net_status)
        + sizeof(net_protocol_version)
        + sizeof(net_crypto_suite)
        + sizeof(vpr_uuid)
        + suite->key_cipher_opts.public_key_size
        + suite->key_cipher_opts.minimum_nonce_size
        + suite->key_cipher_opts.minimum_nonce_size
        + suite->mac_short_opts.mac_size;

    /* clear the response structure. */
    memset(resp, 0, sizeof(*resp));

    /* set the disposer. */
    resp->hdr.dispose = &dispose_protocol_resp_handshake_request;

    /* is this at least large enough for the failure case? */
    if (payload_size < expected_fail_payload_size)
    {
        retval = VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_PAYLOAD_SIZE;
        goto cleanup_resp;
    }

    /* byte pointer for convenience. */
    const uint8_t* buf = (const uint8_t*)payload;

    /* read the request_id. */
    memcpy(&net_request_id, buf, sizeof(net_request_id));
    resp->request_id = ntohl(net_request_id);
    buf += sizeof(net_request_id);
    if (PROTOCOL_REQ_ID_HANDSHAKE_INITIATE != resp->request_id)
    {
        retval = VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_VALUE;
        goto cleanup_resp;
    }

    /* read the request offset. */
    memcpy(&net_offset, buf, sizeof(net_offset));
    resp->offset = ntohl(net_offset);
    buf += sizeof(net_offset);

    /* read the status. */
    memcpy(&net_status, buf, sizeof(net_status));
    resp->status = ntohl(net_status);
    buf += sizeof(net_status);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != resp->status)
    {
        retval = VCBLOCKCHAIN_STATUS_SUCCESS;
        goto cleanup_resp;
    }

    /* if the status is success, then verify that we have a full payload. */
    if (payload_size != expected_full_payload_size)
    {
        retval = VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_PAYLOAD_SIZE;
        goto cleanup_resp;
    }

    /* copy the protocol version. */
    memcpy(&net_protocol_version, buf, sizeof(net_protocol_version));
    resp->protocol_version = ntohl(net_protocol_version);
    buf += sizeof(net_protocol_version);
    if (PROTOCOL_VERSION_0_1_DEMO != resp->protocol_version)
    {
        retval = VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_VALUE;
        goto cleanup_resp;
    }

    /* copy the crypto suite. */
    memcpy(&net_crypto_suite, buf, sizeof(net_crypto_suite));
    resp->crypto_suite = ntohl(net_crypto_suite);
    buf += sizeof(net_crypto_suite);
    if (VCCRYPT_SUITE_VELO_V1 != resp->crypto_suite)
    {
        retval = VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_VALUE;
        goto cleanup_resp;
    }

    /* copy the agent id. */
    memcpy(&resp->agent_id, buf, sizeof(resp->agent_id));
    buf += sizeof(resp->agent_id);

    /* allocate the server public key buffer. */
    retval =
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            suite, &resp->server_public_key);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_resp;
    }

    /* copy the public key. */
    memcpy(resp->server_public_key.data, buf, resp->server_public_key.size);
    buf += resp->server_public_key.size;
    resp->server_public_key_set = true;

    /* allocate the server key nonce. */
    retval =
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            suite, &resp->server_key_nonce);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_resp;
    }

    /* copy the key nonce. */
    memcpy(resp->server_key_nonce.data, buf, resp->server_key_nonce.size);
    buf += resp->server_key_nonce.size;
    resp->server_key_nonce_set = true;

    /* allocate the server challenge nonce. */
    retval =
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            suite, &resp->server_challenge_nonce);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_resp;
    }

    /* copy the challenge nonce. */
    memcpy(
        resp->server_challenge_nonce.data, buf,
        resp->server_challenge_nonce.size);
    buf += resp->server_challenge_nonce.size;
    resp->server_challenge_nonce_set = true;

    /* allocate the server cr hmac. */
    retval =
        vccrypt_suite_buffer_init_for_mac_authentication_code(
            suite, &resp->server_cr_hmac, true);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_resp;
    }

    /* copy the cr hmac. */
    memcpy(resp->server_cr_hmac.data, buf, resp->server_cr_hmac.size);
    buf += resp->server_cr_hmac.size;
    resp->server_cr_hmac_set = true;

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;
    /* on success, the response struct is owned by the caller. */
    goto done;

cleanup_resp:
    dispose((disposable_t*)resp);

done:
    return retval;
}

/**
 * \brief Dispose of the response structure.
 *
 * \param disp          Opaque pointer to the response structure to dispose.
 */
static void dispose_protocol_resp_handshake_request(void* disp)
{
    protocol_resp_handshake_request* resp =
        (protocol_resp_handshake_request*)disp;

    /* clean up server public key if set. */
    if (resp->server_public_key_set)
    {
        dispose((disposable_t*)&resp->server_public_key);
    }

    /* clean up server key nonce if set. */
    if (resp->server_key_nonce_set)
    {
        dispose((disposable_t*)&resp->server_key_nonce);
    }

    /* clean up server challenge nonce if set. */
    if (resp->server_challenge_nonce_set)
    {
        dispose((disposable_t*)&resp->server_challenge_nonce);
    }

    /* clean up server cr hmac if set. */
    if (resp->server_cr_hmac_set)
    {
        dispose((disposable_t*)&resp->server_cr_hmac);
    }

    /* clear the structure. */
    memset(resp, 0, sizeof(*resp));
}
