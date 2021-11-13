/**
 * \file protocol/vcblockchain_protocol_decode_resp_handshake_ack.c
 *
 * \brief Decode a handshake ack response into a response structure.
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
static void dispose_protocol_resp_handshake_ack(void* disp);

/**
 * \brief Decode a handshake ack response using the given parameters.
 *
 * \param resp                      The decoded response buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p resp structure is initialized with the decoded values.
 * The caller owns this structure and must \ref dispose() it when it is no
 * longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_resp_handshake_ack(
    protocol_resp_handshake_ack* resp,
    const void* payload, size_t payload_size)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != resp);
    MODEL_ASSERT(NULL != payload);

    /* compute payload size. */
    size_t expected_payload_size = 3 * sizeof(uint32_t);

    /* is the payload the expected size? */
    if (payload_size != expected_payload_size)
    {
        return VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_PAYLOAD_SIZE;
    }

    /* get a uint32_t pointer to the payload for convenience. */
    const uint32_t* valarray = (const uint32_t*)payload;

    /* initialize the response structure. */
    memset(resp, 0, sizeof(*resp));
    resp->hdr.dispose = &dispose_protocol_resp_handshake_ack;
    resp->request_id = ntohl(valarray[0]);
    resp->status = ntohl(valarray[1]);
    resp->offset = ntohl(valarray[2]);

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}

/**
 * \brief Dispose of the response structure.
 *
 * \param disp          Opaque pointer to the response structure to dispose.
 */
static void dispose_protocol_resp_handshake_ack(void* disp)
{
    protocol_resp_handshake_ack* resp = (protocol_resp_handshake_ack*)disp;

    /* clear out structure. */
    memset(resp, 0, sizeof(protocol_resp_handshake_ack));
}
