/**
 * \file vcblockchain/protocol/data.h
 *
 * \brief Data for blockchain protocol.
 *
 * \copyright 2020-2022 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCBLOCKCHAIN_PROTOCOL_DATA_HEADER_GUARD
#define VCBLOCKCHAIN_PROTOCOL_DATA_HEADER_GUARD

#include <vccrypt/buffer.h>
#include <vpr/disposable.h>
#include <vpr/uuid.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief Request IDs for the blockchain protocol.
 */
typedef enum protocol_request_id
{
    PROTOCOL_REQ_ID_HANDSHAKE_INITIATE = 0x00000000,
    PROTOCOL_REQ_ID_HANDSHAKE_ACKNOWLEDGE = 0x00000001,
    PROTOCOL_REQ_ID_LATEST_BLOCK_ID_GET = 0x00000002,
    PROTOCOL_REQ_ID_TRANSACTION_SUBMIT = 0x00000003,
    PROTOCOL_REQ_ID_BLOCK_BY_ID_GET = 0x00000004,
    PROTOCOL_REQ_ID_BLOCK_ID_GET_NEXT = 0x00000005,
    PROTOCOL_REQ_ID_BLOCK_ID_GET_PREV = 0x00000006,
    PROTOCOL_REQ_ID_BLOCK_ID_BY_HEIGHT_GET = 0x00000007,

    PROTOCOL_REQ_ID_TRANSACTION_BY_ID_GET = 0x00000010,
    PROTOCOL_REQ_ID_TRANSACTION_ID_GET_NEXT = 0x00000011,
    PROTOCOL_REQ_ID_TRANSACTION_ID_GET_PREV = 0x00000012,
    PROTOCOL_REQ_ID_TRANSACTION_ID_GET_BLOCK_ID = 0x00000013,

    PROTOCOL_REQ_ID_ARTIFACT_FIRST_TXN_BY_ID_GET = 0x00000020,
    PROTOCOL_REQ_ID_ARTIFACT_LAST_TXN_BY_ID_GET = 0x00000021,

    PROTOCOL_REQ_ID_ASSERT_LATEST_BLOCK_ID = 0x00000030,
    PROTOCOL_REQ_ID_ASSERT_LATEST_BLOCK_ID_CANCEL = 0x00000031,

    PROTOCOL_REQ_ID_STATUS_GET = 0x0000A000,

    PROTOCOL_REQ_ID_CLOSE = 0x0000FFFF,
} protocol_request_id;

/**
 * \brief Supported protocol versions.
 */
typedef enum protocol_version
{
    PROTOCOL_VERSION_0_1_DEMO = 0x00000001,
    PROTOCOL_VERSION_0_2_FORWARD_SECRECY = 0x00000002,
} protocol_version;

/**
 * \brief The decoded protocol request for the handshake request.
 */
typedef struct protocol_req_handshake_request
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol version. */
    uint32_t protocol_version;
    /** \brief the crypto suite. */
    uint32_t crypto_suite;
    /** \brief the client uuid. */
    vpr_uuid client_id;
    /** \brief the client key nonce. */
    vccrypt_buffer_t client_key_nonce;
    /** \brief the client challenge nonce. */
    vccrypt_buffer_t client_challenge_nonce;
} protocol_req_handshake_request;

/**
 * \brief The decoded protocol response for the handshake request.
 */
typedef struct protocol_resp_handshake_request
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the protocol version. */
    uint32_t protocol_version;
    /** \brief the crypto suite. */
    uint32_t crypto_suite;
    /** \brief the agent uuid. */
    vpr_uuid agent_id;
    /** \brief flag to determine whether public key is set. */
    bool server_public_key_set;
    /** \brief the server public key. */
    vccrypt_buffer_t server_public_key;
    /** \brief flag to determine whether key nonce is set. */
    bool server_key_nonce_set;
    /** \brief the server key nonce. */
    vccrypt_buffer_t server_key_nonce;
    /** \brief flag to determine whether challenge nonce is set. */
    bool server_challenge_nonce_set;
    /** \brief the server challenge nonce. */
    vccrypt_buffer_t server_challenge_nonce;
    /** \brief flag to determine whether cr hmac is set. */
    bool server_cr_hmac_set;
    /** \brief the server response to the client challenge. */
    vccrypt_buffer_t server_cr_hmac;
} protocol_resp_handshake_request;

/**
 * \brief The decoded protocol request for the handshake ack.
 */
typedef struct protocol_req_handshake_ack
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the C/R digest. */
    vccrypt_buffer_t digest;
} protocol_req_handshake_ack;

/**
 * \brief The decoded protocol response for the handshake ack request.
 */
typedef struct protocol_resp_handshake_ack
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
} protocol_resp_handshake_ack;

/**
 * \brief The decoded protocol request for the latest block id get request.
 */
typedef struct protocol_req_latest_block_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
} protocol_req_latest_block_id_get;

/**
 * \brief The decoded protocol response for the latest block id get response.
 */
typedef struct protocol_resp_latest_block_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the block id. */
    vpr_uuid block_id;
} protocol_resp_latest_block_id_get;

/**
 * \brief The decoded protocol request for the transaction submit request.
 */
typedef struct protocol_req_transaction_submit
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the transaction id. */
    vpr_uuid txn_id;
    /** \brief the artifact id. */
    vpr_uuid artifact_id;
    /** \brief the certificate. */
    vccrypt_buffer_t cert;
} protocol_req_transaction_submit;

/**
 * \brief The decoded protocol response for the transaction submit response.
 */
typedef struct protocol_resp_transaction_submit
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
} protocol_resp_transaction_submit;

/**
 * \brief The decoded protocol request for the block get request.
 */
typedef struct protocol_req_block_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the transaction id. */
    vpr_uuid block_id;
} protocol_req_block_get;

/**
 * \brief The decoded protocol response for the block get response.
 */
typedef struct protocol_resp_block_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the block id. */
    vpr_uuid block_id;
    /** \brief the previous block id. */
    vpr_uuid prev_block_id;
    /** \brief the next block id. */
    vpr_uuid next_block_id;
    /** \brief the first transaction id in the block. */
    vpr_uuid first_txn_id;
    /** \brief the block height. */
    uint64_t block_height;
    /** \brief the serialized block size. */
    uint64_t block_size;
    /** \brief the block certificate. */
    vccrypt_buffer_t block_cert;
} protocol_resp_block_get;

/**
 * \brief The decoded protocol request for the block next id get request.
 */
typedef struct protocol_req_block_next_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the block id. */
    vpr_uuid block_id;
} protocol_req_block_next_id_get;

/**
 * \brief The decoded protocol response for the block next id get response.
 */
typedef struct protocol_resp_block_next_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the next block id. */
    vpr_uuid next_block_id;
} protocol_resp_block_next_id_get;

/**
 * \brief The decoded protocol request for the block prev id get request.
 */
typedef struct protocol_req_block_prev_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the block id. */
    vpr_uuid block_id;
} protocol_req_block_prev_id_get;

/**
 * \brief The decoded protocol response for the block prev id get response.
 */
typedef struct protocol_resp_block_prev_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the prev block id. */
    vpr_uuid prev_block_id;
} protocol_resp_block_prev_id_get;

/**
 * \brief The decoded protocol request for the artifact first txn id get
 * request.
 */
typedef struct protocol_req_artifact_first_txn_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the artifact id. */
    vpr_uuid artifact_id;
} protocol_req_artifact_first_txn_id_get;

/**
 * \brief The decoded protocol response for the artifact first txn id get
 * response.
 */
typedef struct protocol_resp_artifact_first_txn_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the first transaction id. */
    vpr_uuid first_txn_id;
} protocol_resp_artifact_first_txn_id_get;

/**
 * \brief The decoded protocol request for the artifact last txn id get
 * request.
 */
typedef struct protocol_req_artifact_last_txn_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the artifact id. */
    vpr_uuid artifact_id;
} protocol_req_artifact_last_txn_id_get;

/**
 * \brief The decoded protocol response for the artifact last txn id get
 * response.
 */
typedef struct protocol_resp_artifact_last_txn_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the last transaction id. */
    vpr_uuid last_txn_id;
} protocol_resp_artifact_last_txn_id_get;

/**
 * \brief The decoded protocol request for the txn get request.
 */
typedef struct protocol_req_txn_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the transaction id. */
    vpr_uuid txn_id;
} protocol_req_txn_get;

/**
 * \brief The decoded protocol response for the transaction get response.
 */
typedef struct protocol_resp_txn_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the transaction id. */
    vpr_uuid txn_id;
    /** \brief the previous transaction id. */
    vpr_uuid prev_txn_id;
    /** \brief the next transaction id. */
    vpr_uuid next_txn_id;
    /** \brief the artifact id to which this transaction belongs. */
    vpr_uuid artifact_id;
    /** \brief the block id for the block in which this transaction was
     * canonized. */
    vpr_uuid block_id;
    /** \brief the serialized transaction state. */
    uint32_t txn_state;
    /** \brief the serialized transaction size. */
    uint64_t txn_size;
    /** \brief the transaction certificate. */
    vccrypt_buffer_t txn_cert;
} protocol_resp_txn_get;

/**
 * \brief The decoded protocol request for the block id by height get request.
 */
typedef struct protocol_req_block_id_by_height_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the block height. */
    uint64_t height;
} protocol_req_block_id_by_height_get;

/**
 * \brief The decoded protocol response for the block next id get response.
 */
typedef struct protocol_resp_block_id_by_height_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the block id. */
    vpr_uuid block_id;
} protocol_resp_block_id_by_height_get;

/**
 * \brief The decoded protocol request for the transaction next id get request.
 */
typedef struct protocol_req_txn_next_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the txn id. */
    vpr_uuid txn_id;
} protocol_req_txn_next_id_get;

/**
 * \brief The decoded protocol response for the transaction next id get
 * response.
 */
typedef struct protocol_resp_txn_next_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the next txn id. */
    vpr_uuid next_txn_id;
} protocol_resp_txn_next_id_get;

/**
 * \brief The decoded protocol request for the transaction prev id get request.
 */
typedef struct protocol_req_txn_prev_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the txn id. */
    vpr_uuid txn_id;
} protocol_req_txn_prev_id_get;

/**
 * \brief The decoded protocol response for the transaction prev id get
 * response.
 */
typedef struct protocol_resp_txn_prev_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the prev txn id. */
    vpr_uuid prev_txn_id;
} protocol_resp_txn_prev_id_get;

/**
 * \brief The decoded protocol request for the transaction block id get request.
 */
typedef struct protocol_req_txn_block_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the txn id. */
    vpr_uuid txn_id;
} protocol_req_txn_block_id_get;

/**
 * \brief The decoded protocol response for the transaction block id get
 * response.
 */
typedef struct protocol_resp_txn_block_id_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
    /** \brief the txn block id. */
    vpr_uuid block_id;
} protocol_resp_txn_block_id_get;

/**
 * \brief The decoded protocol request for the status get request.
 */
typedef struct protocol_req_status_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
} protocol_req_status_get;

/**
 * \brief The decoded protocol response for the status get response.
 */
typedef struct protocol_resp_status_get
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
} protocol_resp_status_get;

/**
 * \brief The decoded protocol request for the connection close request.
 */
typedef struct protocol_req_connection_close
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
} protocol_req_connection_close;

/**
 * \brief The decoded protocol response for the connection close response.
 */
typedef struct protocol_resp_connection_close
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
} protocol_resp_connection_close;

/**
 * \brief The decoded protocol request for the latest block id assertion.
 */
typedef struct protocol_req_assert_latest_block_id
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
    /** \brief the latest block uuid. */
    vpr_uuid latest_block_id;
} protocol_req_assert_latest_block_id;

/**
 * \brief The decoded protocol response for the latest block id assertion.
 */
typedef struct protocol_resp_assert_latest_block_id
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
} protocol_resp_assert_latest_block_id;

/**
 * \brief The decoded protocol request for the latest block id assertion
 * cancellation.
 */
typedef struct protocol_req_assert_latest_block_id_cancel
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the offset. */
    uint32_t offset;
} protocol_req_assert_latest_block_id_cancel;

/**
 * \brief The decoded protocol response for the latest block id assertion
 * cancellation.
 */
typedef struct protocol_resp_assert_latest_block_id_cancel
{
    /** \brief this structure is disposable. */
    disposable_t hdr;
    /** \brief the protocol request id. */
    uint32_t request_id;
    /** \brief the protocol request offset. */
    uint32_t offset;
    /** \brief the protocol response status. */
    uint32_t status;
} protocol_resp_assert_latest_block_id_cancel;

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCBLOCKCHAIN_PROTOCOL_DATA_HEADER_GUARD*/
