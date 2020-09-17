/**
 * \file vcblockchain/protocol/serialization.h
 *
 * \brief Serialization methods for the blockchain protocol.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCBLOCKCHAIN_PROTOCOL_SERIALIZATION_HEADER_GUARD
#define VCBLOCKCHAIN_PROTOCOL_SERIALIZATION_HEADER_GUARD

#include <vcblockchain/protocol/data.h>
#include <vccrypt/suite.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief Encode a handshake request using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded handshake packet.
 * \param suite                     The crypto suite to use for this request.
 * \param offset                    The offset for this request.
 * \param client_id                 The client uuid for this request.
 * \param client_key_nonce          The client key nonce for this request.
 * \param client_challenge_nonce    The client challenge nonce for this request.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_handshake_request(
    vccrypt_buffer_t* buffer, vccrypt_suite_options_t* suite,
    uint32_t offset, const vpr_uuid* client_id,
    const vccrypt_buffer_t* client_key_nonce,
    const vccrypt_buffer_t* client_challenge_nonce);

/**
 * \brief Decode a handshake request using the given parameters.
 *
 * \param req                       The decoded request buffer.
 * \param suite                     The crypto suite to use for this request.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values.  The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_handshake_request(
    protocol_req_handshake_request* req, vccrypt_suite_options_t* suite,
    const void* payload, size_t payload_size);

/**
 * \brief Encode a handshake request response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded handshake response
 *                                  packet.
 * \param suite                     The crypto suite to use for this response.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param agent_id                  The agent uuid for this response.
 * \param server_public_key         The agent public key.
 * \param server_key_nonce          The agent key nonce.
 * \param server_challenge_nonce    The agent challenge nonce.
 * \param server_cr_hmac            The agent response to the client challenge.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_handshake_request(
    vccrypt_buffer_t* buffer, vccrypt_suite_options_t* suite,
    uint32_t offset, uint32_t status, const vpr_uuid* agent_id,
    const vccrypt_buffer_t* server_public_key,
    const vccrypt_buffer_t* server_key_nonce,
    const vccrypt_buffer_t* server_challenge_nonce,
    const vccrypt_buffer_t* server_cr_hmac);

/**
 * \brief Decode a handshake request response using the given parameters.
 *
 * \param resp                      The decoded response buffer.
 * \param suite                     The crypto suite to use for this request.
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
int vcblockchain_protocol_decode_resp_handshake_request(
    protocol_resp_handshake_request* resp, vccrypt_suite_options_t* suite,
    const void* payload, size_t payload_size);

/**
 * \brief Encode a handshake acknowledge request using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded handshake ack packet.
 * \param suite                     The crypto suite to use for this request.
 * \param digest                    Pointer to buffer holding the mac digest.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_handshake_ack(
    vccrypt_buffer_t* buffer, vccrypt_suite_options_t* suite,
    const vccrypt_buffer_t* digest);

/**
 * \brief Decode a handshake ack request using the given parameters.
 *
 * \param req                       The decoded request buffer.
 * \param suite                     The crypto suite to use for this request.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values.  The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_handshake_ack(
    protocol_req_handshake_ack* req, vccrypt_suite_options_t* suite,
    const void* payload, size_t payload_size);

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
    uint32_t offset, uint32_t status);

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
    const void* payload, size_t payload_size);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCBLOCKCHAIN_PROTOCOL_SERIALIZATION_HEADER_GUARD*/
