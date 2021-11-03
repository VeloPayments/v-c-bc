/**
 * \file protocol/vcblockchain_protocol_sendreq_handshake_request.c
 *
 * \brief Send a handshake request to the server.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vcblockchain/ssock.h>
#include <vpr/parameters.h>

/**
 * \brief Send a handshake request to the API.
 *
 * \param sock              The socket to which this request is written.
 * \param suite             The crypto suite to use for this handshake.
 * \param client_id         The entity UUID for the client.
 * \param key_nonce         Buffer to receive the client key nonce for this
 *                          request. This buffer must not have been previously
 *                          initialized. On success, this is initialized and
 *                          owned by the caller; it must be disposed by the
 *                          caller when no longer needed.
 * \param challenge_nonce   Buffer to receive the client challenge nonce for
 *                          this request.  This buffer must not have been
 *                          previously initialized. On success, this is owned by
 *                          the caller and must be disposed.
 *
 * This function generates entropy data for the nonces based on the suite.  This
 * data is passed to the server. On a successful return from this function, the
 * key_nonce and challenge_nonce buffers are initialized with this entropy data
 * and must not be disposed by the caller.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if a write to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if an out-of-memory issue was
 *        encountered.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_sendreq_handshake_request(
    ssock* sock, vccrypt_suite_options_t* suite, const vpr_uuid* client_id,
    vccrypt_buffer_t* key_nonce, vccrypt_buffer_t* challenge_nonce)
{
    int retval = 0;

    /* parameter sanity check. */
    MODEL_ASSERT(sock >= 0);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != client_id);
    MODEL_ASSERT(NULL != key_nonce);
    MODEL_ASSERT(NULL != challenge_nonce);

    /* create prng. */
    vccrypt_prng_context_t prng;
    retval = vccrypt_suite_prng_init(suite, &prng);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* initialize key nonce buffer. */
    retval =
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            suite, key_nonce);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_prng;
    }

    /* read key nonce from prng. */
    retval = vccrypt_prng_read(&prng, key_nonce, key_nonce->size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_key_nonce;
    }

    /* initialize challenge nonce buffer. */
    retval =
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            suite, challenge_nonce);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_key_nonce;
    }

    /* read challenge nonce from prng. */
    retval = vccrypt_prng_read(&prng, challenge_nonce, challenge_nonce->size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_challenge_nonce;
    }

    /* create handshake request payload buffer. */
    vccrypt_buffer_t payload;
    retval =
        vcblockchain_protocol_encode_req_handshake_request(
            &payload, suite, 0U, client_id, key_nonce, challenge_nonce);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_challenge_nonce;
    }

    /* write data packet with request payload to socket. */
    size_t write_size = payload.size;
    retval = ssock_write_data(sock, payload.data, write_size);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_payload;
    }

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;

cleanup_payload:
    dispose((disposable_t*)&payload);

cleanup_challenge_nonce:
    if (retval != VCBLOCKCHAIN_STATUS_SUCCESS)
    {
        dispose((disposable_t*)challenge_nonce);
    }

cleanup_key_nonce:
    if (retval != VCBLOCKCHAIN_STATUS_SUCCESS)
    {
        dispose((disposable_t*)key_nonce);
    }

cleanup_prng:
    dispose((disposable_t*)&prng);

done:
    return retval;
}
