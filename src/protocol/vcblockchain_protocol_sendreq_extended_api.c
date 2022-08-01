/**
 * \file protocol/vcblockchain_protocol_sendreq_extended_api.c
 *
 * \brief Send an extended api request to the server.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Send an extended API request.
 *
 * \param sock                      The socket to which this request is written.
 * \param suite                     The crypto suite to use for this request.
 * \param client_iv                 Pointer to the client IV, updated by this
 *                                  call.
 * \param shared_secret             The shared secret to use for this request.
 * \param offset                    The offset to use for this request. It
 *                                  should be unique per any outbound request
 *                                  for which a response has not yet been
 *                                  received.
 * \param entity_id                 The entity to which this request should be
 *                                  sent.
 * \param verb_id                   The verb id for this request.
 * \param request_body              The body of the request to be sent.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_sendreq_extended_api(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* entity_id, const vpr_uuid* verb_id,
    const vccrypt_buffer_t* request_body)
{
    int retval;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != shared_secret);
    MODEL_ASSERT(NULL != entity_id);
    MODEL_ASSERT(NULL != verb_id);
    MODEL_ASSERT(NULL != request_body);

    /* encode the request. */
    vccrypt_buffer_t buffer;
    retval =
        vcblockchain_protocol_encode_req_extended_api(
            &buffer, suite->alloc_opts, offset, entity_id, verb_id,
            request_body);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* write the IPC authed data packet to the server. */
    retval =
        ssock_write_authed_data(
            sock, *client_iv, buffer.data, buffer.size, suite, shared_secret);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_buffer;
    }

    /* increment client IV. */
    *client_iv += 1;

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;

cleanup_buffer:
    dispose((disposable_t*)&buffer);

done:
    return retval;
}
