/**
 * \file protocol/vcblockchain_protocol_recvresp_handshake_request.c
 *
 * \brief Receive a handshake request response from the server.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vcblockchain/ssock.h>
#include <vccrypt/compare.h>

/**
 * \brief Receive a handshake response from the API.
 *
 * \param sock                      The socket from which this response is read.
 * \param suite                     The crypto suite to use to verify this
 *                                  response.
 * \param server_id                 The uuid pointer to receive the server's
 *                                  uuid.
 * \param server_pubkey             The buffer to hold the public key received
 *                                  from the server. THIS SHOULD BE VERIFIED BY
 *                                  THE CALLER TO PREVENT MITM ATTACKS. This
 *                                  buffer should not be initialized prior to
 *                                  calling this function. On success, it is
 *                                  initialized and populated with the server
 *                                  public key. This is owned by the caller and
 *                                  must be disposed when no longer needed.
 * \param client_privkey            The client private key.
 * \param client_key_nonce          The client key nonce for this handshake.
 * \param client_challenge_nonce    The client challenge nonce for this
 *                                  handshake.
 * \param server_challenge_nonce    The buffer to receive the server's challenge
 *                                  nonce. Must not have been previously
 *                                  initialized. On success, it is initialized
 *                                  and populated with the server challenge
 *                                  nonce. This is owned by the caller and must
 *                                  be disposed when no longer needed.
 * \param shared_secret             The buffer to receive the shared secret for
 *                                  this session. Must not have been previously
 *                                  initialized. On success, it is initialized
 *                                  and populated with the shared secret. This
 *                                  is owned by the caller and must be disposed
 *                                  when no longer needed.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 *
 * On a successful return from this function, the status is updated with the
 * status code from the API request.  This status should be checked. A zero
 * status indicates the request to the remote peer was successful, and a
 * non-zero status indicates that the request to the remote peer failed.
 *
 * The handshake is verified, and an error is returned if this verification
 * fails. On success, the computed shared secret is written to the \p
 * shared_secret parameter, which is owned by the caller and must be disposed
 * when no longer needed.  Likewise, the \p server_pubkey and
 * \p server_challenge-nonce buffers are written and owned by the caller, and
 * must be disposed when no longer needed.
 *
 * \note TO PREVENT A MAN-IN-THE-MIDDLE ATTACK, the \p server_pubkey must be
 * compared against a cached server public key. If these do not match, then the
 * connection cannot be trusted, even if verification succeeded above.
 *
 * If the status code is updated with an error from the service, then this error
 * will be reflected in the status variable, even though a
 * \ref VCBLOCKCHAIN_STATUS_SUCCESS was returned by this function. Thus, both
 * the return value of this function AND the status code must be checked to
 * ensure correct operation.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if an out-of-memory condition was
 *        encountered.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_recvresp_handshake_request(
    ssock* sock, vccrypt_suite_options_t* suite, vpr_uuid* server_id,
    vccrypt_buffer_t* server_pubkey,
    const vccrypt_buffer_t* client_privkey,
    const vccrypt_buffer_t* client_key_nonce,
    const vccrypt_buffer_t* client_challenge_nonce,
    vccrypt_buffer_t* server_challenge_nonce,
    vccrypt_buffer_t* shared_secret, uint32_t* offset, uint32_t* status)
{
    int retval = 0;

    /* parameter sanity check. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != server_id);
    MODEL_ASSERT(NULL != server_pubkey);
    MODEL_ASSERT(NULL != client_privkey);
    MODEL_ASSERT(NULL != client_key_nonce);
    MODEL_ASSERT(NULL != client_challenge_nonce);
    MODEL_ASSERT(NULL != server_challenge_nonce);
    MODEL_ASSERT(NULL != shared_secret);
    MODEL_ASSERT(NULL != offset);
    MODEL_ASSERT(NULL != status);

    /* read a data packet from the socket. */
    void* val = NULL;
    uint32_t size = 0;
    retval = ssock_read_data(sock, suite->alloc_opts, &val, &size);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* decode the packet. */
    protocol_resp_handshake_request resp;
    retval =
        vcblockchain_protocol_decode_resp_handshake_request(
            &resp, suite, val, size);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_val;
    }

    /* if the response status is not success, then short circuit. */
    if (VCBLOCKCHAIN_STATUS_SUCCESS != (int)resp.status)
    {
        retval = (int)resp.status;
        goto cleanup_resp;
    }

    /* create a buffer for the shared secret. */
    vccrypt_buffer_t local_shared_secret;
    retval =
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            suite, &local_shared_secret);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_resp;
    }

    /* create key derivation instance. */
    vccrypt_key_agreement_context_t agreement;
    retval =
        vccrypt_suite_cipher_key_agreement_init(
            suite, &agreement);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_shared_secret;
    }

    /* derive shared secret. */
    retval =
        vccrypt_key_agreement_short_term_secret_create(
            &agreement, client_privkey, &resp.server_public_key,
            &resp.server_key_nonce, client_key_nonce,
            &local_shared_secret);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_key_agreement;
    }

    /* create the mac instance. */
    vccrypt_mac_context_t mac;
    retval = vccrypt_suite_mac_short_init(suite, &mac, &local_shared_secret);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_key_agreement;
    }

    /* create hmac buffer. */
    vccrypt_buffer_t local_hmac_buffer;
    retval =
        vccrypt_suite_buffer_init_for_mac_authentication_code(
            suite, &local_hmac_buffer, true);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_mac;
    }

    /* digest the payload, minus the mac. */
    retval =
        vccrypt_mac_digest(
            &mac, (const uint8_t*)val, size - local_hmac_buffer.size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_local_hmac_buffer;
    }

    /* add the client challenge to the digest. */
    retval =
        vccrypt_mac_digest(
            &mac, (const uint8_t*)client_challenge_nonce->data,
            client_challenge_nonce->size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_local_hmac_buffer;
    }

    /* finalize the mac. */
    retval = vccrypt_mac_finalize(&mac, &local_hmac_buffer);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_local_hmac_buffer;
    }

    /* verify that the hmac matches. */
    if (0 !=
            crypto_memcmp(
                local_hmac_buffer.data, resp.server_cr_hmac.data,
                local_hmac_buffer.size))
    {
        retval = VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_VALUE;
        goto cleanup_local_hmac_buffer;
    }

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;

    /* copy the server id. */
    memcpy(server_id, &resp.agent_id, sizeof(resp.agent_id));

    /* move the agent public key. */
    vccrypt_buffer_move(server_pubkey, &resp.server_public_key);

    /* move the server challenge nonce. */
    vccrypt_buffer_move(server_challenge_nonce, &resp.server_challenge_nonce);

    /* move the shared secret. */
    vccrypt_buffer_move(shared_secret, &local_shared_secret);

    /* copy offset and status. */
    *offset = resp.offset;
    *status = resp.status;

cleanup_local_hmac_buffer:
    dispose((disposable_t*)&local_hmac_buffer);

cleanup_mac:
    dispose((disposable_t*)&mac);

cleanup_key_agreement:
    dispose((disposable_t*)&agreement);

cleanup_shared_secret:
    dispose((disposable_t*)&local_shared_secret);

cleanup_resp:
    dispose((disposable_t*)&resp);

cleanup_val:
    memset(val, 0, size);
    free(val);

done:
    return retval;
}
