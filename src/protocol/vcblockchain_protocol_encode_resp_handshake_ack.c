/**
 * \file protocol/vcblockchain_protocol_encode_resp_handshake_ack.c
 *
 * \brief Encode a handshake ack response into a buffer.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <string.h>

/**
 * \brief Encode a handshake ack response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded handshake response
 *                                  packet.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_handshake_ack(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != buffer);
    MODEL_ASSERT(NULL != alloc_opts);

    const uint32_t net_request_id =
        htonl(PROTOCOL_REQ_ID_HANDSHAKE_ACKNOWLEDGE);
    const uint32_t net_offset = htonl(offset);
    const uint32_t net_status = htonl(status);

    /* | Handshake response response packet.                                | */
    /* | --------------------------------------------------- | ------------ | */
    /* | DATA                                                | SIZE         | */
    /* | --------------------------------------------------- | ------------ | */
    /* | UNAUTH_PROTOCOL_REQ_ID_HANDSHAKE_ACKNOWLEDGE        |   4 bytes    | */
    /* | offset                                              |   4 bytes    | */
    /* | status                                              |   4 bytes    | */
    /* | --------------------------------------------------- | ------------ | */

    /* compute the size of the response packet. */
    size_t payload_size =
          sizeof(net_request_id)
        + sizeof(net_offset)
        + sizeof(net_status);

    /* create the output buffer. */
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_buffer_init(buffer, alloc_opts, payload_size))
    {
        return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
    }

    /* write the values to the buffer. */
    uint32_t* buf = (uint32_t*)buffer->data;
    buf[0] = net_request_id;
    buf[1] = net_offset;
    buf[2] = net_status;

    /* success. */
    /* caller owns buffer on success and must dispose it. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
