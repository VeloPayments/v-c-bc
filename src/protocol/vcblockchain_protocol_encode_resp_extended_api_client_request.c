/**
 * \file
 * protocol/vcblockchain_protocol_encode_resp_extended_api_client_request.c
 *
 * \brief Encode an extended api client request response.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode an extended API client request response.
 *
 * \param buffer                    Pointer to an unitialized buffer to receive
 *                                  the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param client_id                 The client entity id for this
 *                                  request/response.
 * \param verb_id                   The verb uuid for this request/response.
 * \param client_enc_pubkey         The client encryption public key.
 * \param client_sign_pubkey        The client signing public key.
 * \param request_body              The request body for this request/response.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response. The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_extended_api_client_request(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint64_t offset,
    const vpr_uuid* client_id, const vpr_uuid* verb_id,
    const vccrypt_buffer_t* client_enc_pubkey,
    const vccrypt_buffer_t* client_sign_pubkey,
    const vccrypt_buffer_t* request_body)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != client_id);
    MODEL_ASSERT(NULL != verb_id);
    MODEL_ASSERT(NULL != client_enc_pubkey);
    MODEL_ASSERT(NULL != client_sign_pubkey);
    MODEL_ASSERT(NULL != request_body);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts || NULL == client_id
     || NULL == verb_id || NULL == client_enc_pubkey
     || NULL == client_sign_pubkey || NULL == request_body)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* create the buffer. */
    size_t resp_size =
        sizeof(uint32_t) /* request offset. */
      + sizeof(uint64_t) /* offset. */
      + 2 * 16 /* client id and verb id. */
      + 2 * sizeof(uint32_t) /* key sizes. */
      + client_enc_pubkey->size
      + client_sign_pubkey->size
      + request_body->size;
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, resp_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* work with a byte array for convenience. */
    uint8_t* barr = (uint8_t*)buffer->data;

    /* populate the request id. */
    uint32_t net_method_id = htonl(PROTOCOL_REQ_ID_EXTENDED_API_CLIENTREQ);
    memcpy(barr, &net_method_id, sizeof(net_method_id));
    barr += sizeof(net_method_id);

    /* populate the offset. */
    uint64_t net_offset = htonll(offset);
    memcpy(barr, &net_offset, sizeof(net_offset));
    barr += sizeof(net_offset);

    /* populate the client encryption pubkey size. */
    uint32_t net_enc_key_size = htonl(client_enc_pubkey->size);
    memcpy(barr, &net_enc_key_size, sizeof(net_enc_key_size));
    barr += sizeof(net_enc_key_size);

    /* populate the client signing pubkey size. */
    uint32_t net_sign_key_size = htonl(client_sign_pubkey->size);
    memcpy(barr, &net_sign_key_size, sizeof(net_sign_key_size));
    barr += sizeof(net_sign_key_size);

    /* populate the client id. */
    memcpy(barr, client_id, sizeof(*client_id));
    barr += sizeof(*client_id);

    /* populate the verb id. */
    memcpy(barr, verb_id, sizeof(*verb_id));
    barr += sizeof(*verb_id);

    /* populate the encryption pubkey. */
    memcpy(barr, client_enc_pubkey->data, client_enc_pubkey->size);
    barr += client_enc_pubkey->size;

    /* populate the signing pubkey. */
    memcpy(barr, client_sign_pubkey->data, client_sign_pubkey->size);
    barr += client_sign_pubkey->size;

    /* copy the response body. */
    memcpy(barr, request_body->data, request_body->size);
    barr += request_body->size;

    /* success. */
    /* On success, the caller owns the buffer and must dispose it. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
