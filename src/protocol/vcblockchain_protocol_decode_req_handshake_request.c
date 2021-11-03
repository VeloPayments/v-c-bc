/**
 * \file protocol/vcblockchain_protocol_decode_req_handshake_request.c
 *
 * \brief Decode a handshake request into a request structure.
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
static void dispose_protocol_req_handshake_request(void* disp);

/**
 * \brief Decode a handshake request using the given parameters.
 *
 * \param req                       The decoded request buffer.
 * \param suite                     The crypto suite to use for this request.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values.  The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_handshake_request(
    protocol_req_handshake_request* req, vccrypt_suite_options_t* suite,
    const void* payload, size_t payload_size)
{
    int retval;
    uint32_t net_request_id, net_offset, net_protocol_version;
    uint32_t net_crypto_suite;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != req);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != payload);

    /* compute the expected payload size. */
    size_t expected_payload_size =
          sizeof(net_request_id)
        + sizeof(net_offset)
        + sizeof(net_protocol_version)
        + sizeof(net_crypto_suite)
        + sizeof(vpr_uuid)
        + suite->key_cipher_opts.minimum_nonce_size
        + suite->key_cipher_opts.minimum_nonce_size;

    /* verify that this size matches what we expect. */
    if (payload_size != expected_payload_size)
    {
        retval = VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_PAYLOAD_SIZE;
        goto done;
    }

    /* set up the request buffer. */
    memset(req, 0, sizeof(protocol_req_handshake_request));
    req->hdr.dispose = &dispose_protocol_req_handshake_request;

    /* allocate client_key_nonce buffer. */
    retval =
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            suite, &req->client_key_nonce);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_req;
    }

    /* allocate client_challenge_nonce buffer. */
    retval =
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            suite, &req->client_challenge_nonce);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_client_key_nonce;
    }

    /* byte pointer for convenience. */
    const uint8_t* buf = (const uint8_t*)payload;

    /* read the request id. */
    memcpy(&net_request_id, buf, sizeof(net_request_id));
    req->request_id = ntohl(net_request_id);
    buf += sizeof(net_request_id);
    if (PROTOCOL_REQ_ID_HANDSHAKE_INITIATE != req->request_id)
    {
        retval = VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_VALUE;
        goto cleanup_client_challenge_nonce;
    }

    /* read the request offset. */
    memcpy(&net_offset, buf, sizeof(net_offset));
    req->offset = ntohl(net_offset);
    buf += sizeof(net_offset);

    /* read the protocol version. */
    memcpy(&net_protocol_version, buf, sizeof(net_protocol_version));
    req->protocol_version = ntohl(net_protocol_version);
    buf += sizeof(net_protocol_version);
    if (PROTOCOL_VERSION_0_1_DEMO != req->protocol_version)
    {
        retval = VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_VALUE;
        goto cleanup_client_challenge_nonce;
    }

    /* read the crypto suite. */
    memcpy(&net_crypto_suite, buf, sizeof(net_crypto_suite));
    req->crypto_suite = ntohl(net_crypto_suite);
    buf += sizeof(net_crypto_suite);
    if (req->crypto_suite != suite->suite_id)
    {
        retval = VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_VALUE;
        goto cleanup_client_challenge_nonce;
    }

    /* read the client entity id. */
    memcpy(&req->client_id, buf, sizeof(req->client_id));
    buf += sizeof(req->client_id);

    /* read the client key nonce. */
    memcpy(req->client_key_nonce.data, buf, req->client_key_nonce.size);
    buf += req->client_key_nonce.size;

    /* read the client challenge nonce. */
    memcpy(
        req->client_challenge_nonce.data, buf,
        req->client_challenge_nonce.size);
    buf += req->client_challenge_nonce.size;

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;
    /* on success, the request struct is owned by the caller. */
    goto done;

cleanup_client_challenge_nonce:
    dispose((disposable_t*)&req->client_challenge_nonce);

cleanup_client_key_nonce:
    dispose((disposable_t*)&req->client_key_nonce);

cleanup_req:
    memset(req, 0, sizeof(protocol_req_handshake_request));

done:
    return retval;
}

/**
 * \brief Dispose of the decoded request buffer.
 */
static void dispose_protocol_req_handshake_request(void* disp)
{
    protocol_req_handshake_request* req = (protocol_req_handshake_request*)disp;

    /* clean up the client key nonce. */
    dispose((disposable_t*)&req->client_key_nonce);
    /* clean up the client challenge nonce. */
    dispose((disposable_t*)&req->client_challenge_nonce);

    /* clear the structure. */
    memset(req, 0, sizeof(protocol_req_handshake_request));
}
