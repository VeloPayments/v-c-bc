/**
 * \file protocol/vcblockchain_protocol_sendreq_extended_api_enable.c
 *
 * \brief Send an extended api enable request to the server.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>
#include <vcblockchain/psock.h>

/**
 * \brief Send an extended API enable request.
 *
 * This request enables the connected entity to field extended API requests to
 * it through the blockchain agent. The blockchain agent will authenticate and
 * authorize other entities wishing to send requests to this entity, but from
 * there, will only forward requests to this entity. It is up to this entity to
 * perform any additional parameter checks on any requests it receives.
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
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status vcblockchain_protocol_sendreq_extended_api_enable(
    RCPR_SYM(psock)* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset)
{
    int retval;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != shared_secret);

    /* encode the request. */
    vccrypt_buffer_t buffer;
    retval =
        vcblockchain_protocol_encode_req_extended_api_enable(
            &buffer, suite->alloc_opts, offset);
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
