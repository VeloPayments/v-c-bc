/**
 * \file vcblockchain/protocol.h
 *
 * \brief Protocol abstraction layer for communicating with the blockchain
 * agent.
 *
 * \copyright 2020-2022 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCBLOCKCHAIN_PROTOCOL_HEADER_GUARD
#define VCBLOCKCHAIN_PROTOCOL_HEADER_GUARD

#include <vcblockchain/ssock.h>
#include <vccrypt/suite.h>
#include <vpr/allocator.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief Send a handshake request to the API.
 *
 * \param sock              The socket to which this request is written.
 * \param suite             The crypto suite to use for this handshake.
 * \param client_id         The entity UUID for the client.
 * \param key_nonce         Buffer to receive the client key nonce for this
 *                          request. This buffer must not have been previously
 *                          initialized. On success, this is initialized and
 *                          owned by the caller; it must be disposed by the
 *                          caller when no longer needed.
 * \param challenge_nonce   Buffer to receive the client challenge nonce for
 *                          this request.  This buffer must not have been
 *                          previously initialized. On success, this is owned by
 *                          the caller and must be disposed.
 *
 * This function generates entropy data for the nonces based on the suite.  This
 * data is passed to the server. On a successful return from this function, the
 * key_nonce and challenge_nonce buffers are initialized with this entropy data
 * and must not be disposed by the caller.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if a write to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if an out-of-memory issue was
 *        encountered.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_sendreq_handshake_request(
    ssock* sock, vccrypt_suite_options_t* suite, const vpr_uuid* client_id,
    vccrypt_buffer_t* key_nonce, vccrypt_buffer_t* challenge_nonce);

/**
 * \brief Receive a handshake response from the API.
 *
 * \param sock                      The socket from which this response is read.
 * \param suite                     The crypto suite to use to verify this
 *                                  response.
 * \param server_id                 The uuid pointer to receive the server's
 *                                  uuid.
 * \param server_pubkey             The buffer to hold the public key received
 *                                  from the server. THIS SHOULD BE VERIFIED BY
 *                                  THE CALLER TO PREVENT MITM ATTACKS. This
 *                                  buffer should not be initialized prior to
 *                                  calling this function. On success, it is
 *                                  initialized and populated with the server
 *                                  public key. This is owned by the caller and
 *                                  must be disposed when no longer needed.
 * \param client_privkey            The client private key.
 * \param client_key_nonce          The client key nonce for this handshake.
 * \param client_challenge_nonce    The client challenge nonce for this
 *                                  handshake.
 * \param server_challenge_nonce    The buffer to receive the server's challenge
 *                                  nonce. Must not have been previously
 *                                  initialized. On success, it is initialized
 *                                  and populated with the server challenge
 *                                  nonce. This is owned by the caller and must
 *                                  be disposed when no longer needed.
 * \param shared_secret             The buffer to receive the shared secret for
 *                                  this session. Must not have been previously
 *                                  initialized. On success, it is initialized
 *                                  and populated with the shared secret. This
 *                                  is owned by the caller and must be disposed
 *                                  when no longer needed.
 * \param offset                    The offset for this response.
 * \param status                    The status for this response.
 *
 * On a successful return from this function, the status is updated with the
 * status code from the API request.  This status should be checked. A zero
 * status indicates the request to the remote peer was successful, and a
 * non-zero status indicates that the request to the remote peer failed.
 *
 * The handshake is verified, and an error is returned if this verification
 * fails. On success, the computed shared secret is written to the \p
 * shared_secret parameter, which is owned by the caller and must be disposed
 * when no longer needed.  Likewise, the \p server_pubkey and
 * \p server_challenge-nonce buffers are written and owned by the caller, and
 * must be disposed when no longer needed.
 *
 * \note TO PREVENT A MAN-IN-THE-MIDDLE ATTACK, the \p server_pubkey must be
 * compared against a cached server public key. If these do not match, then the
 * connection cannot be trusted, even if verification succeeded above.
 *
 * If the status code is updated with an error from the service, then this error
 * will be reflected in the status variable, even though a
 * \ref VCBLOCKCHAIN_STATUS_SUCCESS was returned by this function. Thus, both
 * the return value of this function AND the status code must be checked to
 * ensure correct operation.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if an out-of-memory condition was
 *        encountered.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_recvresp_handshake_request(
    ssock* sock, vccrypt_suite_options_t* suite, vpr_uuid* server_id,
    vccrypt_buffer_t* server_pubkey,
    const vccrypt_buffer_t* client_privkey,
    const vccrypt_buffer_t* client_key_nonce,
    const vccrypt_buffer_t* client_challenge_nonce,
    vccrypt_buffer_t* server_challenge_nonce,
    vccrypt_buffer_t* shared_secret, uint32_t* offset, uint32_t* status);

/**
 * \brief Send a handshake acknowledge to the API.
 *
 * \param sock                      The socket to which this request is written.
 * \param suite                     The crypto suite to use for this handshake.
 * \param client_iv                 Pointer to receive the updated client IV.
 * \param server_iv                 Pointer to receive the updated server IV.
 * \param shared_secret             The shared secret key for this request.
 * \param server_challenge_nonce    The server challenge nonce for this request.
 *
 * This function sends the handshake acknowledgement as an authorized packet to
 * the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_handshake_ack(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    uint64_t* server_iv, const vccrypt_buffer_t* shared_secret,
    const vccrypt_buffer_t* server_challenge_nonce);

/**
 * \brief Send a get latest block id request to the API.
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
 *
 * This function sends the get latest block request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_latest_block_id_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset);

/**
 * \brief Send a transaction submission request.
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
 * \param txn_id                    The transaction id for this request.
 * \param artifact_id               The artifact id for this request.
 * \param cert                      Pointer to the certificate for this request.
 * \param cert_size                 The size of this certificate.
 *
 * This function sends a transaction submission request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_transaction_submit(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* txn_id, const vpr_uuid* artifact_id, const void* cert,
    size_t cert_size);

/**
 * \brief Send a block get request.
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
 * \param block_id                  The block UUID to get, or zero_uuid for the
 *                                  first block, or 0xff uuid for last block.
 *
 * This function sends a block get request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_block_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* block_id);

/**
 * \brief Send a block get next id request.
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
 * \param block_id                  The block UUID to get, or zero_uuid for the
 *                                  first block, or 0xff uuid for last block.
 *
 * This function sends a block get request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_block_next_id_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* block_id);

/**
 * \brief Send a block get prev id request.
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
 * \param block_id                  The block UUID to get, or zero_uuid for the
 *                                  first block, or 0xff uuid for last block.
 *
 * This function sends a block get prev id request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_block_prev_id_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* block_id);

/**
 * \brief Send a block id by height get request.
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
 * \param height                    The block height for which to query the
 *                                  block id.
 *
 * This function sends a block get request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_block_id_by_height_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset, uint64_t height);

/**
 * \brief Send an artifact get first transaction id request.
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
 * \param artifact_id               The artifact UUID to get.
 *
 * This function sends an artifact get first transaction request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_artifact_first_txn_id_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* artifact_id);

/**
 * \brief Send an artifact get last transaction id request.
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
 * \param artifact_id               The artifact UUID to get.
 *
 * This function sends an artifact get last transaction request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_artifact_last_txn_id_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* artifact_id);

/**
 * \brief Send a txn get request.
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
 * \param txn_id                    The transaction UUID to get.
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
int vcblockchain_protocol_sendreq_txn_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* txn_id);

/**
 * \brief Send a transaction get next id request.
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
int vcblockchain_protocol_sendreq_txn_next_id_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* txn_id);

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
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* txn_id);

/**
 * \brief Send a transaction get block id request.
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
 * This function sends a transaction get block id request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_txn_block_id_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* txn_id);

/**
 * \brief Send a status get request.
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
 *
 * This function sends a status get request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_status_get(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset);

/**
 * \brief Send a connection close request.
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
 *
 * This function sends a connection close request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_connection_close(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset);

/**
 * \brief Send a latest block id assertion request.
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
 * \param latest_block_id           The latest block id for this request.
 *
 * This function sends a connection close request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_assert_latest_block_id(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset,
    const vpr_uuid* latest_block_id);

/**
 * \brief Send a latest block assertion cancellation request.
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
 *
 * This function sends a connection close request to the server.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing to the socket failed.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - a non-zero error response if something else has failed.
 */
int vcblockchain_protocol_sendreq_assert_latest_block_id_cancel(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    const vccrypt_buffer_t* shared_secret, uint32_t offset);

/**
 * \brief Send an extended API enable request.
 *
 * This request enables the connected entity to field extended API requests to
 * it through the blockchain agent. The blockchain agent will authenticate and
 * authorize other entities wishing to send requests to this entity, but from
 * there, will only forward requests to this entity. It is up to this entity to
 * perform any additional parameter checks on any requests it receives.
 *
 * \param sock                      The socket to which this request is written.
 * \param suite                     The crypto suite to use for this request.
 * \param client_iv                 Pointer to the client IV, updated by this
 *                                  call.
 * \param shared_secret             The shared secret to use for this request.
 * \param offset                    The offset to use for this request. It
 *                                  should be unique per any outbound request
 *                                  for which a response has not yet been
 *                                  received.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_sendreq_extended_api_enable(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    vccrypt_buffer_t* shared_secret, uint32_t offset);

/**
 * \brief Send an extended API request.
 *
 * \param sock                      The socket to which this request is written.
 * \param suite                     The crypto suite to use for this request.
 * \param client_iv                 Pointer to the client IV, updated by this
 *                                  call.
 * \param shared_secret             The shared secret to use for this request.
 * \param offset                    The offset to use for this request. It
 *                                  should be unique per any outbound request
 *                                  for which a response has not yet been
 *                                  received.
 * \param entity_id                 The entity to which this request should be
 *                                  sent.
 * \param verb_id                   The verb id for this request.
 * \param request_body              The body of the request to be sent.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_sendreq_extended_api(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    vccrypt_buffer_t* shared_secret, uint32_t offset, const vpr_uuid* entity_id,
    const vpr_uuid* verb_id, const vccrypt_buffer_t* request_body);

/**
 * \brief Send a response to an extended API request.
 *
 * \param sock                      The socket to which this request is written.
 * \param suite                     The crypto suite to use for this request.
 * \param client_iv                 Pointer to the client IV, updated by this
 *                                  call.
 * \param shared_secret             The shared secret to use for this request.
 * \param offset                    The offset provided by agentd for the
 *                                  original extended request. Unlike regular
 *                                  offsets, these are 64-bit and are only used
 *                                  once.
 * \param status                    The status to pass to the client.
 * \param response_body             The body of the response to be sent.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_protocol_sendreq_extended_api_response(
    ssock* sock, vccrypt_suite_options_t* suite, uint64_t* client_iv,
    vccrypt_buffer_t* shared_secret, uint64_t offset, uint32_t status,
    const vccrypt_buffer_t* response_body);

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
    vccrypt_buffer_t* shared_secret, vccrypt_buffer_t* response);

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
    const vccrypt_buffer_t* response);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCBLOCKCHAIN_PROTOCOL_HEADER_GUARD*/
