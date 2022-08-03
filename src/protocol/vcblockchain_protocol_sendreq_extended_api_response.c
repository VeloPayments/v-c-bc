/**
 * \file protocol/vcblockchain_protocol_sendreq_extended_api_response.c
 *
 * \brief Send an extended api response request to the server.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>
#include <vcblockchain/psock.h>

/**
 * \brief Send a response to an extended API request.
 *
 * \param sock                      The socket to which this request is written.
 * \param suite                     The crypto suite to use for this request.
 * \param client_iv                 Pointer to the client IV, updated by this
 *                                  call.
 * \param shared_secret             The shared secret to use for this request.
 * \param offset                    The offset provided by agentd for the
 *                                  original extended request. Unlike regular
 *                                  offsets, these are 64-bit and are only used
 *                                  once.
 * \param status                    The status to pass to the client.
 * \param response_body             The body of the response to be sent.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status vcblockchain_protocol_sendreq_extended_api_response(
    RCPR_SYM(psock)* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint64_t offset, uint32_t status,
    const vccrypt_buffer_t* response_body)
{
    int retval;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != shared_secret);
    MODEL_ASSERT(NULL != response_body);

    /* encode the request. */
    vccrypt_buffer_t buffer;
    retval =
        vcblockchain_protocol_encode_req_extended_api_response(
            &buffer, suite->alloc_opts, offset, status, response_body);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* write the IPC authed data packet to the server. */
    retval =
        psock_write_authed_data(
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
