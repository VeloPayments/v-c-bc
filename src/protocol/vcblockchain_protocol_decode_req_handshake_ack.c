/**
 * \file protocol/vcblockchain_protocol_decode_req_handshake_ack.c
 *
 * \brief Decode a handshake acknowledge request into a request structure.
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
static void dispose_protocol_req_handshake_ack(void* disp);

/**
 * \brief Decode a handshake ack request using the given parameters.
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
int vcblockchain_protocol_decode_req_handshake_ack(
    protocol_req_handshake_ack* req, vccrypt_suite_options_t* suite,
    const void* payload, size_t payload_size)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != req);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != payload);

    /* set up the request buffer. */
    memset(req, 0, sizeof(protocol_req_handshake_ack));
    req->hdr.dispose = &dispose_protocol_req_handshake_ack;

    /* allocate digest buffer. */
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(
            &req->digest, suite->alloc_opts, payload_size))
    {
        memset(req, 0, sizeof(protocol_req_handshake_ack));
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* copy the payload to the buffer. */
    MODEL_ASSERT(req->digest.size == payload_size);
    memcpy(req->digest.data, payload, req->digest.size);

    /* success. */
    /* on success, caller owns req and must dispose it. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of the decoded request buffer.
 */
static void dispose_protocol_req_handshake_ack(void* disp)
{
    protocol_req_handshake_ack* req = (protocol_req_handshake_ack*)disp;

    /* clean up the digest. */
    dispose((disposable_t*)&req->digest);

    /* clear the structure. */
    memset(req, 0, sizeof(protocol_req_handshake_ack));
}
