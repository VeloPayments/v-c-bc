/**
 * \file protocol/vcblockchain_protocol_recvresp.c
 *
 * \brief Receive a request response from the server.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/protocol.h>

/**
 * \brief Receive a response from the API.
 *
 * \param sock                      The socket from which this response is read.
 * \param suite                     The crypto suite to use for this read.
 * \param server_iv                 Pointer to the server_iv to use, updated as
 *                                  a consequence of this call.
 * \param shared_secret             The shared secret key for this request.
 * \param response                  Pointer to an uninitialized buffer. On
 *                                  success, this buffer is initialized with the
 *                                  response and must be disposed by the caller
 *                                  when no longer needed.
 *
 * \note - this function requires that the handshake request send / receive, and
 * the handshake ack send have each been performed before it can be used.
 *
 * This call reads a response from the protocol. On success, the server_iv is
 * incremented, and the response buffer is initialized with the response
 * received, and must be disposed by the caller when no longer needed. This
 * response is the raw bytes of the response as decrypted by this call. The
 * caller can decode this response into a structure by calling \ref
 * vcblockchain_protocol_response_decode.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_recvresp(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* server_iv,
    vccrypt_buffer_t* shared_secret, vccrypt_buffer_t* response)
{
    int retval;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != server_iv);
    MODEL_ASSERT(NULL != shared_secret);
    MODEL_ASSERT(NULL != response);

    /* runtime parameter checks. */
    if (NULL == sock || NULL == suite || NULL == server_iv
     || NULL == shared_secret || NULL == response)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto done;
    }

    /* read an authed data packet from the server. */
    void* val = NULL;
    uint32_t size = 0U;
    retval =
        ssock_read_authed_data(
            sock, suite->alloc_opts, *server_iv, &val, &size, suite,
            shared_secret);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* create a crypto buffer large enough to hold the response. */
    retval = vccrypt_buffer_init(response, suite->alloc_opts, size);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_val;
    }

    /* copy the response to this buffer. */
    MODEL_ASSERT(size == response->size);
    memcpy(response->data, val, response->size);

    /* increment the server iv. */
    ++(*server_iv);

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;
    /* the response buffer is owned by the caller on success. */

cleanup_val:
    memset(val, 0, size);
    release(suite->alloc_opts, val);

done:
    return retval;
}
