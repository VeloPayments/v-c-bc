/**
 * \file
 * protocol/vcblockchain_protocol_decode_resp_extended_api_client_request.c
 *
 * \brief Decode an extended API client request response into a struct.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/* forward decls. */
static void dispose_protocol_resp_extended_api_client_request(void* disp);

/**
 * \brief Decode an extended API client request response.
 *
 * \param resp                      The decoded response buffer.
 * \param alloc_opts                The allocator options to use for this
 *                                  operation.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p resp structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_resp_extended_api_client_request(
    protocol_resp_extended_api_client_request* resp,
    allocator_options_t* alloc_opts, const void* payload, size_t payload_size)
{
    int retval;

    /* parameter sanity check. */
    MODEL_ASSERT(NULL != resp);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != payload);

    /* runtime parameter checks. */
    if (NULL == resp || NULL == alloc_opts || NULL == payload)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto done;
    }

    /* payload size check. */
    const size_t resp_size =
        sizeof(uint32_t)
      + sizeof(uint64_t)
      + 2 * 16
      + 2 * sizeof(uint32_t);
    if (payload_size < resp_size)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto done;
    }

    /* initialize the response structure. */
    memset(resp, 0, sizeof(*resp));
    resp->hdr.dispose = &dispose_protocol_resp_extended_api_client_request;
    const uint8_t* barr = (const uint8_t*)payload;

    /* copy the request id. */
    uint32_t net_request_id;
    memcpy(&net_request_id, barr, sizeof(net_request_id));
    barr += sizeof(net_request_id);
    resp->request_id = ntohl(net_request_id);

    /* copy the offset. */
    uint64_t net_offset;
    memcpy(&net_offset, barr, sizeof(net_offset));
    barr += sizeof(net_offset);
    resp->offset = ntohll(net_offset);

    /* copy the client encryption pubkey size. */
    uint32_t client_enc_pubkey_size;
    memcpy(&client_enc_pubkey_size, barr, sizeof(client_enc_pubkey_size));
    barr += sizeof(client_enc_pubkey_size);
    client_enc_pubkey_size = ntohl(client_enc_pubkey_size);

    /* copy the client signing pubkey size. */
    uint32_t client_sign_pubkey_size;
    memcpy(&client_sign_pubkey_size, barr, sizeof(client_sign_pubkey_size));
    barr += sizeof(client_sign_pubkey_size);
    client_sign_pubkey_size = ntohl(client_sign_pubkey_size);

    /* second payload size check. */
    const size_t extended_resp_size =
        resp_size + client_enc_pubkey_size + client_sign_pubkey_size;
    if (payload_size < extended_resp_size)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto cleanup_resp;
    }

    /* copy the client id. */
    memcpy(&resp->client_id, barr, sizeof(resp->client_id));
    barr += sizeof(resp->client_id);

    /* copy the verb id. */
    memcpy(&resp->verb_id, barr, sizeof(resp->verb_id));
    barr += sizeof(resp->verb_id);

    /* initialize the client encryption pubkey buffer. */
    if (VCCRYPT_STATUS_SUCCESS
     != vccrypt_buffer_init(
            &resp->client_enc_pubkey, alloc_opts, client_enc_pubkey_size))
    {
        retval = VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
        goto cleanup_resp;
    }

    /* copy the client encryption pubkey. */
    memcpy(resp->client_enc_pubkey.data, barr, resp->client_enc_pubkey.size);
    barr += resp->client_enc_pubkey.size;

    /* initialize the client signing pubkey buffer. */
    if (VCCRYPT_STATUS_SUCCESS
     != vccrypt_buffer_init(
            &resp->client_sign_pubkey, alloc_opts, client_sign_pubkey_size))
    {
        retval = VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
        goto cleanup_resp;
    }

    /* copy the client signing pubkey. */
    memcpy(resp->client_sign_pubkey.data, barr, resp->client_sign_pubkey.size);
    barr += resp->client_sign_pubkey.size;

    /* compute the size of the response body. */
    const size_t request_body_size = payload_size - extended_resp_size;

    /* create the request body buffer. */
    if (VCCRYPT_STATUS_SUCCESS
        != vccrypt_buffer_init(
                &resp->request_body, alloc_opts, request_body_size))
    {
        retval = VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
        goto cleanup_resp;
    }

    /* copy the response body data. */
    memcpy(resp->request_body.data, barr, resp->request_body.size);
    barr += resp->request_body.size;

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;
    /* on success, resp is owned by the caller. */
    goto done;

cleanup_resp:
    dispose((disposable_t*)resp);

done:
    return retval;
}

/**
 * \brief Dispose of a decoded response structure.
 *
 * \param disp      The structure to dispose.
 */
static void dispose_protocol_resp_extended_api_client_request(void* disp)
{
    protocol_resp_extended_api_client_request* resp =
        (protocol_resp_extended_api_client_request*)disp;

    /* dispose of client encryption pubkey if set. */
    if (NULL != resp->client_enc_pubkey.data)
    {
        dispose((disposable_t*)&resp->client_enc_pubkey);
    }

    /* dispose of client signing pubkey if set. */
    if (NULL != resp->client_sign_pubkey.data)
    {
        dispose((disposable_t*)&resp->client_sign_pubkey);
    }

    /* dispose of buffer if set. */
    if (NULL != resp->request_body.data)
    {
        dispose((disposable_t*)&resp->request_body);
    }

    memset(resp, 0, sizeof(protocol_resp_extended_api_client_request));
}
