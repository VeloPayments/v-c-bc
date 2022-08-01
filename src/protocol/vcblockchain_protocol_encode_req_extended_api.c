/**
 * \file
 * protocol/vcblockchain_protocol_encode_req_extended_api.c
 *
 * \brief Encode an extended API request.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>

/**
 * \brief Encode an extended API request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this operation.
 * \param offset                    The offset to use for this request.
 * \param entity_id                 The entity UUID of the requested API.
 * \param verb_id                   The verb UUID to be performed on this
 *                                  entity.
 * \param request_body              The body of the request to be sent.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request. The caller owns this buffer and must \ref dispose() it when it is no
 * longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_extended_api(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint32_t offset,
    const vpr_uuid* entity_id, const vpr_uuid* verb_id,
    const vccrypt_buffer_t* request_body)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);

    /* runtime parameter checks. */
    if (NULL == buffer || NULL == alloc_opts || NULL == entity_id
     || NULL == verb_id || NULL == request_body)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* compute the buffer size. */
    size_t buffer_size =
        2 * sizeof(uint32_t) /* request_id and offset */
      + 2 * 16 /* entity id and verb id. */
      + request_body->size;

    /* initialize the buffer. */
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, buffer_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* write the request id and offset. */
    uint32_t* u32arr = (uint32_t*)buffer->data;
    u32arr[0] = htonl(PROTOCOL_REQ_ID_EXTENDED_API_SENDRECV);
    u32arr[1] = htonl(offset);

    /* write remaining values. */
    uint8_t* u8arr = (uint8_t*)(u32arr + 2);
    memcpy(u8arr, entity_id, sizeof(*entity_id)); u8arr += sizeof(*entity_id);
    memcpy(u8arr, verb_id, sizeof(*verb_id)); u8arr += sizeof(*verb_id);
    memcpy(u8arr, request_body->data, request_body->size);

    /* success. */
    /* buffer is owned by the caller on success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
