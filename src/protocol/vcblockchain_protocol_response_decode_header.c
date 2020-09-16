/**
 * \file protocol/vcblockchain_protocol_response_decode_header.c
 *
 * \brief Decode values from the response header.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <vcblockchain/protocol.h>

/**
 * \brief Decode the header values of a response.
 *
 * \param request_id                Pointer to receive the request id on
 *                                  success.
 * \param offset                    Pointer to receive the offset on success.
 * \param status                    Pointer to receive the status on success.
 * \param response                  The response received from the protocol.
 *
 * This method reads the header values from the response. The \p request_id can
 * be used to decode and dispatch a response based on specific details. The
 * \p offset ties this response to a previous request sent by the caller. The
 * \p status indicates whether a given request was successful or not, which may
 * determine whether additional information is available for decoding. A
 * specific response should ONLY be decoded if the status code was successful.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if an invalid argument was encountered.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_response_decode_header(
    uint32_t* request_id, uint32_t* offset, uint32_t* status,
    const vccrypt_buffer_t* response)
{
    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != request_id);
    MODEL_ASSERT(NULL != offset);
    MODEL_ASSERT(NULL != status);
    MODEL_ASSERT(NULL != response);

    /* runtime parameter check. */
    if ( NULL == request_id || NULL == offset || NULL == status
      || NULL == response)
    {
        return VCBLOCKCHAIN_ERROR_INVALID_ARG;
    }

    /* verify that the buffer is a sufficient size. */
    size_t header_size = 3 * sizeof(uint32_t);
    if (response->size < header_size)
    {
        return VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_PAYLOAD_SIZE;
    }

    /* copy the header data. */
    const uint32_t* u32buf = (const uint32_t*)response->data;
    *request_id = ntohl(u32buf[0]);
    *offset = ntohl(u32buf[1]);
    *status = ntohl(u32buf[2]);

    /* success. */
    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
