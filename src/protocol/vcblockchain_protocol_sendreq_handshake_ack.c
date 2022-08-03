/**
 * \file protocol/vcblockchain_protocol_sendreq_handshake_ack.c
 *
 * \brief Send a handshake ack request to the server.
 *
 * \copyright 2020-2022 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/psock.h>

/**
 * \brief Send a handshake acknowledge to the API.
 *
 * \param sock                      The socket to which this request is written.
 * \param suite                     The crypto suite to use for this handshake.
 * \param client_iv                 Pointer to receive the updated client IV.
 * \param server_iv                 Pointer to receive the updated server IV.
 * \param shared_secret             The shared secret key for this request.
 * \param server_challenge_nonce    The server challenge nonce for this request.
 *
 * This function sends the handshake acknowledgement as an authorized packet to
 * the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
status vcblockchain_protocol_sendreq_handshake_ack(
    RCPR_SYM(psock)* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    uint64_t* server_iv, const vccrypt_buffer_t* shared_secret,
    const vccrypt_buffer_t* server_challenge_nonce)
{
    int retval;

    /* parameter sanity checking. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(NULL != shared_secret);
    MODEL_ASSERT(NULL != server_challenge_nonce);

    /* create a buffer for holding the digest. */
    vccrypt_buffer_t digest;
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_suite_buffer_init_for_mac_authentication_code(
            suite, &digest, true))
    {
        retval = VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    /* create a mac instance for building the response to the challenge. */
    vccrypt_mac_context_t mac;
    retval =
        vccrypt_suite_mac_short_init(
            suite, &mac, (vccrypt_buffer_t*)shared_secret);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_digest;
    }

    /* digest the server challenge nonce. */
    retval =
        vccrypt_mac_digest(
            &mac, server_challenge_nonce->data, server_challenge_nonce->size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_mac;
    }

    /* finalize the digest. */
    retval = vccrypt_mac_finalize(&mac, &digest);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_mac;
    }

    /* set the client and server IVs. */
    *client_iv = 0x0000000000000001;
    *server_iv = 0x8000000000000001;

    /* write the IPC authed data packet to the server. */
    retval =
        psock_write_authed_data(
            sock, *client_iv, digest.data, digest.size, suite, shared_secret);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_mac;
    }

    /* increment client IV. */
    *client_iv += 1;

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;

cleanup_mac:
    dispose((disposable_t*)&mac);

cleanup_digest:
    dispose((disposable_t*)&digest);

done:
    return retval;
}
