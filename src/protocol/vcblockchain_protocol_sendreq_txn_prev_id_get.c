/**
 * \file protocol/vcblockchain_protocol_sendreq_txn_prev_id_get.c
 *
 * \brief Send a txn prev id get request to the server.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Send a transaction get prev id request.
 *
 * \param sock                      The socket to which this request is written.
 * \param suite                     The crypto suite to use for this handshake.
 * \param client_iv                 Pointer to the client IV, updated by this
 *                                  call.
 * \param shared_secret             The shared secret key for this request.
 * \param offset                    The offset to use for this request. It
 *                                  should be unique per any outbound request
 *                                  for which a response has not yet been
 *                                  received.
 * \param txn_id                    The txn UUID to query.
 *
 * This function sends a transaction get request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_txn_prev_id_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    vccrypt_buffer_t* shared_secret, uint32_t offset, const vpr_uuid* txn_id)
{
    int retval;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != client_iv);
    MODEL_ASSERT(NULL != shared_secret);
    MODEL_ASSERT(NULL != txn_id);

    /* encode the request. */
    vccrypt_buffer_t buffer;
    retval =
        vcblockchain_protocol_encode_req_txn_prev_id_get(
            &buffer, suite->alloc_opts, offset, txn_id);
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
