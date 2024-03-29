/**
 * \file vcblockchain/protocol/serialization.h
 *
 * \brief Serialization methods for the blockchain protocol.
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
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

/**
 * \brief Encode a latest block id get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_latest_block_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset);

/**
 * \brief Decode a latest block id get request.
 *
 * \param req                       The decoded request buffer.
 * \param alloc_opts                The allocator options to use.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_latest_block_id_get(
    protocol_req_latest_block_id_get* req, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size);

/**
 * \brief Encode a latest block id get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param block_id                  The latest block id.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_latest_block_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* block_id);

/**
 * \brief Decode a latest block id get response.
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
int vcblockchain_protocol_decode_resp_latest_block_id_get(
    protocol_resp_latest_block_id_get* resp,
    const void* payload, size_t payload_size);

/**
 * \brief Encode a transaction submit request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param txn_id                    The id of this transaction.
 * \param artifact_id               The artifact id of this transaction.
 * \param cert                      Pointer to the certificate data for this
 *                                  transaction.
 * \param cert_size                 The size of this certificate in bytes.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_transaction_submit(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* txn_id, const vpr_uuid* artifact_id,
    const void* cert, size_t cert_size);

/**
 * \brief Decode a transaction submit request.
 *
 * \param req                       The decoded request buffer.
 * \param alloc_opts                The allocator options to use.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_transaction_submit(
    protocol_req_transaction_submit* req, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size);

/**
 * \brief Encode a transaction submit response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
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
int vcblockchain_protocol_encode_resp_transaction_submit(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status);

/**
 * \brief Decode a transaction submit response.
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
int vcblockchain_protocol_decode_resp_transaction_submit(
    protocol_resp_transaction_submit* resp,
    const void* payload, size_t payload_size);

/**
 * \brief Encode a block get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param block_id                  The id of block to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_block_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* block_id);

/**
 * \brief Decode a block get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_block_get(
    protocol_req_block_get* req, const void* payload, size_t payload_size);

/**
 * \brief Encode a block get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param block_id                  The block id.
 * \param prev_block_id             The previous block id.
 * \param next_block_id             The next block id.
 * \param first_txn_id              The first transaction id in the block.
 * \param block_height              The block height.
 * \param ser_block_cert_size       The serialized block cert size.
 * \param block_cert                Pointer to the start of the block
 *                                  certificate.
 * \param block_cert_size           The block cert size.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_block_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* block_id,
    const vpr_uuid* prev_block_id, const vpr_uuid* next_block_id,
    const vpr_uuid* first_txn_id, uint64_t block_height,
    uint64_t ser_block_cert_size, const void* block_cert,
    size_t block_cert_size);

/**
 * \brief Decode a block get response.
 *
 * \param resp                      The decoded response buffer.
 * \param alloc_opts                The allocator to use for this response.
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
int vcblockchain_protocol_decode_resp_block_get(
    protocol_resp_block_get* resp, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size);

/**
 * \brief Encode a block next id get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param block_id                  The id of block to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_block_next_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* block_id);

/**
 * \brief Decode a block next id get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_block_next_id_get(
    protocol_req_block_next_id_get* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a block next id get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param next_block_id             The next block id.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_block_next_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* next_block_id);

/**
 * \brief Decode a block next id get response.
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
int vcblockchain_protocol_decode_resp_block_next_id_get(
    protocol_resp_block_next_id_get* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a block prev id get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param block_id                  The id of block to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_block_prev_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* block_id);

/**
 * \brief Decode a block prev id get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_block_prev_id_get(
    protocol_req_block_prev_id_get* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a block prev id get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param prev_block_id             The prev block id.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_block_prev_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* prev_block_id);

/**
 * \brief Decode a block prev id get response.
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
int vcblockchain_protocol_decode_resp_block_prev_id_get(
    protocol_resp_block_prev_id_get* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode an artifact first txn id get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param artifact_id               The id of artifact to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_artifact_first_txn_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* artifact_id);

/**
 * \brief Decode an artifact first txn id get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_artifact_first_txn_id_get(
    protocol_req_artifact_first_txn_id_get* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode an artifact first txn id get response using the given
 * parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param first_txn_id              The first transaction id.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_artifact_first_txn_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* first_txn_id);

/**
 * \brief Decode an artifact first txn id get response.
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
int vcblockchain_protocol_decode_resp_artifact_first_txn_id_get(
    protocol_resp_artifact_first_txn_id_get* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode an artifact last txn id get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param artifact_id               The id of artifact to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_artifact_last_txn_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* artifact_id);

/**
 * \brief Decode an artifact last txn id get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_artifact_last_txn_id_get(
    protocol_req_artifact_last_txn_id_get* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode an artifact last txn id get response using the given
 * parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param last_txn_id               The last transaction id.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_artifact_last_txn_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* last_txn_id);

/**
 * \brief Decode an artifact last txn id get response.
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
int vcblockchain_protocol_decode_resp_artifact_last_txn_id_get(
    protocol_resp_artifact_last_txn_id_get* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a transaction get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param txn_id                    The id of transaction to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_txn_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* txn_id);

/**
 * \brief Decode a transaction get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_txn_get(
    protocol_req_txn_get* req, const void* payload, size_t payload_size);

/**
 * \brief Encode a transaction get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param txn_id                    The transaction id.
 * \param prev_txn_id               The previous transaction id.
 * \param next_txn_id               The next transaction id.
 * \param artifact_id               The artifact id for this transaction.
 * \param block_id                  The block id for this transaction.
 * \param ser_txn_cert_size         The serialized transaction cert size.
 * \param txn_cert                  Pointer to the start of the transaction
 *                                  certificate.
 * \param txn_cert_size             The transaction cert size.
 * \param txn_state                 The transaction state.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_txn_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* txn_id,
    const vpr_uuid* prev_txn_id, const vpr_uuid* next_txn_id,
    const vpr_uuid* artifact_id, const vpr_uuid* block_id,
    uint64_t ser_txn_cert_size, const void* txn_cert, size_t txn_cert_size,
    uint32_t txn_state);

/**
 * \brief Decode a transaction get response.
 *
 * \param resp                      The decoded response buffer.
 * \param alloc_opts                The allocator to use for this response.
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
int vcblockchain_protocol_decode_resp_txn_get(
    protocol_resp_txn_get* resp, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size);

/**
 * \brief Encode a block id by height get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param height                    The block height of block id to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_block_id_by_height_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint64_t height);

/**
 * \brief Decode a block id by height get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_block_id_by_height_get(
    protocol_req_block_id_by_height_get* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a block id by height get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param block_id                  The block id.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_block_id_by_height_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* block_id);

/**
 * \brief Decode a block id by height get response.
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
int vcblockchain_protocol_decode_resp_block_id_by_height_get(
    protocol_resp_block_id_by_height_get* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a transaction next id get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param txn_id                    The id of txn to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_txn_next_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* txn_id);

/**
 * \brief Decode a transaction next id get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_txn_next_id_get(
    protocol_req_txn_next_id_get* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a transaction next id get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param next_txn_id               The next txn id.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_txn_next_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* next_txn_id);

/**
 * \brief Decode a transaction next id get response.
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
int vcblockchain_protocol_decode_resp_txn_next_id_get(
    protocol_resp_txn_next_id_get* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a transaction prev id get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param txn_id                    The id of txn to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_txn_prev_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* txn_id);

/**
 * \brief Decode a transaction prev id get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_txn_prev_id_get(
    protocol_req_txn_prev_id_get* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a transaction prev id get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param prev_txn_id               The prev txn id.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_txn_prev_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* prev_txn_id);

/**
 * \brief Decode a transaction prev id get response.
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
int vcblockchain_protocol_decode_resp_txn_prev_id_get(
    protocol_resp_txn_prev_id_get* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a transaction block id get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param txn_id                    The id of txn to get.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_txn_block_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, const vpr_uuid* txn_id);

/**
 * \brief Decode a transaction block id get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_txn_block_id_get(
    protocol_req_txn_block_id_get* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a transaction block id get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param block_id                  The block id.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_txn_block_id_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status, const vpr_uuid* block_id);

/**
 * \brief Decode a transaction block id get response.
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
int vcblockchain_protocol_decode_resp_txn_block_id_get(
    protocol_resp_txn_block_id_get* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a status get request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_status_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint32_t offset);

/**
 * \brief Decode a status get request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_status_get(
    protocol_req_status_get* req, const void* payload, size_t payload_size);

/**
 * \brief Encode a status get response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
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
int vcblockchain_protocol_encode_resp_status_get(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status);

/**
 * \brief Decode a status get response.
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
int vcblockchain_protocol_decode_resp_status_get(
    protocol_resp_status_get* resp, const void* payload, size_t payload_size);

/**
 * \brief Encode a connection close request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_connection_close(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint32_t offset);

/**
 * \brief Decode a connection close request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_connection_close(
    protocol_req_connection_close* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a connection close response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
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
int vcblockchain_protocol_encode_resp_connection_close(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status);

/**
 * \brief Decode a connection close response.
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
int vcblockchain_protocol_decode_resp_connection_close(
    protocol_resp_connection_close* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode an error response using the given parameters.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param req_id                    The request id for this response.
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
int vcblockchain_protocol_encode_error_resp(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t req_id, uint32_t offset, uint32_t status);

/**
 * \brief Encode a latest block id assertion request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 * \param latest_block_id           The latest block id for this request.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_assert_latest_block_id(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint32_t offset,
    const vpr_uuid* latest_block_id);

/**
 * \brief Decode a latest block id assertion request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_assert_latest_block_id(
    protocol_req_assert_latest_block_id* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a latest block id assertion response.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
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
int vcblockchain_protocol_encode_resp_assert_latest_block_id(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status);

/**
 * \brief Decode a latest block id assertion response.
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
int vcblockchain_protocol_decode_resp_assert_latest_block_id(
    protocol_resp_assert_latest_block_id* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a latest block id assertion cancel request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request.  The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_assert_latest_block_id_cancel(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint32_t offset);

/**
 * \brief Decode a latest block id assertion cancel request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_assert_latest_block_id_cancel(
    protocol_req_assert_latest_block_id_cancel* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode a latest block id assertion cancel response.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
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
int vcblockchain_protocol_encode_resp_assert_latest_block_id_cancel(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status);

/**
 * \brief Decode a latest block id assertion cancel response.
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
int vcblockchain_protocol_decode_resp_assert_latest_block_id_cancel(
    protocol_resp_assert_latest_block_id_cancel* resp, const void* payload,
    size_t payload_size);

/**
 * \brief Encode an extended API enable request.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this request.
 * \param offset                    The offset to use for this request.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request. The caller owns this buffer and must \ref dispose() it when it is no
 * longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_extended_api_enable(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint32_t offset);

/**
 * \brief Decode an extended API enable request.
 *
 * \param req                       The decoded request buffer.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() of it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_extended_api_enable(
    protocol_req_extended_api_enable* req, const void* payload,
    size_t payload_size);

/**
 * \brief Encode an extended API enable response.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response. The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_extended_api_enable(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t offset, uint32_t status);

/**
 * \brief Decode an extended API enable response.
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
int vcblockchain_protocol_decode_resp_extended_api_enable(
    protocol_resp_extended_api_enable* resp, const void* payload,
    size_t payload_size);

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
    const vccrypt_buffer_t* request_body);

/**
 * \brief Decode an extended API request.
 *
 * \param req                       The decoded request buffer.
 * \param alloc_opts                The allocator to use for this operation.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() of it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_extended_api(
    protocol_req_extended_api* req, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size);

/**
 * \brief Encode an extended API response.
 *
 * \param buffer                    Pointer to an unitialized buffer to receive
 *                                  the encoded response.
 * \param alloc_opts                The allocator options to use to allocate the
 *                                  buffer.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 * \param response_body             The response body for this response.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * response. The caller owns this buffer and must \ref dispose() it when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_extended_api(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint32_t offset,
    uint32_t status, const vccrypt_buffer_t* response_body);

/**
 * \brief Decode an extended API response.
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
int vcblockchain_protocol_decode_resp_extended_api(
    protocol_resp_extended_api* resp, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size);

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
    const vccrypt_buffer_t* request_body);

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
    allocator_options_t* alloc_opts, const void* payload, size_t payload_size);

/**
 * \brief Encode an extended API request to send a response to a client.
 *
 * \param buffer                    Pointer to an uninitialized buffer to
 *                                  receive the encoded request packet.
 * \param alloc_opts                The allocator to use for this operation.
 * \param offset                    The offset to use for this request.
 * \param status                    The status to use for this request.
 * \param response_body             The body of the response to be sent.
 *
 * On success, the \p buffer is initialized with a buffer holding the encoded
 * request. The caller owns this buffer and must \ref dispose() it when it is no
 * longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_req_extended_api_response(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts, uint64_t offset,
    uint32_t status, const vccrypt_buffer_t* response_body);

/**
 * \brief Decode an extended API request to send a client response.
 *
 * \param req                       The decoded request buffer.
 * \param alloc_opts                The allocator to use for this operation.
 * \param payload                   Pointer to the payload to decode.
 * \param payload_size              Size of the payload.
 *
 * On success, the \p req structure is initialized with the decoded values. The
 * caller owns this structure and must \ref dispose() of it when it is no longer
 * needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_decode_req_extended_api_response(
    protocol_req_extended_api_response* req, allocator_options_t* alloc_opts,
    const void* payload, size_t payload_size);

/**
 * \brief Encode a generic response for the protocol.
 *
 * \param buffer            An uninitialized buffer to hold the response on
 *                          success.
 * \param alloc_opts        The allocator options to use for this operation.
 * \param request_id        The request id originating this response.
 * \param offset            The client offset for this response.
 * \param status_code       The status code for this response.
 * \param payload           The payload buffer for this response, or NULL for no
 *                          payload.
 * \param payload_size      The size of this payload.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_encode_resp_generic(
    vccrypt_buffer_t* buffer, allocator_options_t* alloc_opts,
    uint32_t request_id, uint32_t offset, uint32_t status_code,
    const void* payload, size_t payload_size);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCBLOCKCHAIN_PROTOCOL_SERIALIZATION_HEADER_GUARD*/
