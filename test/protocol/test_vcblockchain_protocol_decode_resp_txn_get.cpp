/**
 * \file test/protocol/test_vcblockchain_protocol_decode_resp_txn_get.cpp
 *
 * Unit tests for decoding the transaction get response.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(test_vcblockchain_protocol_decode_resp_txn_get, parameters)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    allocator_options_t alloc_opts;
    protocol_resp_txn_get resp;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_resp_txn_get(
            nullptr, &alloc_opts, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_resp_txn_get(
            &resp, nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_resp_txn_get(
            &resp, &alloc_opts, nullptr, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method should verify the payload size.
 */
TEST(test_vcblockchain_protocol_decode_resp_txn_get, payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    allocator_options_t alloc_opts;
    protocol_resp_txn_get resp;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_resp_txn_get(
            &resp, &alloc_opts, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method can decode a properly encoded response message.
 */
TEST(test_vcblockchain_protocol_decode_resp_txn_get, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 52;
    const uint32_t EXPECTED_STATUS = 98;
    const vpr_uuid EXPECTED_TXN_ID = { .data = {
        0x26, 0x49, 0xc3, 0xf4, 0xc6, 0x11, 0x4f, 0x0e,
        0x95, 0xe6, 0x24, 0xd4, 0x12, 0xfc, 0x7c, 0x83 } };
    const vpr_uuid EXPECTED_PREV_TXN_ID = { .data = {
        0xb6, 0xdf, 0x4b, 0xca, 0x3f, 0x9d, 0x43, 0x7c,
        0x92, 0xe6, 0x9f, 0x1e, 0x61, 0xc2, 0xda, 0xe9 } };
    const vpr_uuid EXPECTED_NEXT_TXN_ID = { .data = {
        0x61, 0x77, 0x07, 0xc2, 0x10, 0x7c, 0x4b, 0xb6,
        0x9d, 0x35, 0xa0, 0xf0, 0xde, 0xab, 0x71, 0x05 } };
    const vpr_uuid EXPECTED_ARTIFACT_ID = { .data = {
        0x8f, 0x06, 0xc1, 0xce, 0xea, 0x0c, 0x4f, 0x77,
        0x92, 0xf1, 0x28, 0x86, 0x61, 0xa9, 0x41, 0x78 } };
    const vpr_uuid EXPECTED_BLOCK_ID = { .data = {
        0xd9, 0xc8, 0x66, 0x18, 0xe9, 0xe6, 0x46, 0x88,
        0x8b, 0xe1, 0xb7, 0x7c, 0x7e, 0xac, 0x5a, 0x07 } };
    const uint64_t EXPECTED_SER_TXN_CERT_SIZE = 4;
    const uint32_t EXPECTED_TXN_STATE = 139;
    const uint8_t EXPECTED_TXN_CERT[4] = { 0x01, 0x02, 0x03, 0x04 };
    const size_t EXPECTED_TXN_CERT_SIZE = sizeof(EXPECTED_TXN_CERT);
    allocator_options_t alloc_opts;
    protocol_resp_txn_get resp;
    vccrypt_buffer_t out;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* we can encode this message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_resp_txn_get(
            &out, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_TXN_ID, &EXPECTED_PREV_TXN_ID,
            &EXPECTED_NEXT_TXN_ID, &EXPECTED_ARTIFACT_ID, &EXPECTED_BLOCK_ID,
            EXPECTED_SER_TXN_CERT_SIZE, EXPECTED_TXN_CERT,
            EXPECTED_TXN_CERT_SIZE, EXPECTED_TXN_STATE));

    /* precondition: the response buffer is zeroed out. */
    memset(&resp, 0, sizeof(resp));

    /* we can decode this message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_decode_resp_txn_get(
            &resp, &alloc_opts, out.data, out.size));

    /* the request id is set correctly. */
    EXPECT_EQ(PROTOCOL_REQ_ID_TRANSACTION_BY_ID_GET, resp.request_id);
    /* the offset is set correctly. */
    EXPECT_EQ(EXPECTED_OFFSET, resp.offset);
    /* the status is set correctly. */
    EXPECT_EQ(EXPECTED_STATUS, resp.status);
    /* the txn id is set correctly. */
    EXPECT_EQ(0, memcmp(&resp.txn_id, &EXPECTED_TXN_ID, 16));
    /* the prev txn id is set correctly. */
    EXPECT_EQ(0, memcmp(&resp.prev_txn_id, &EXPECTED_PREV_TXN_ID, 16));
    /* the next txn id is set correctly. */
    EXPECT_EQ(0, memcmp(&resp.next_txn_id, &EXPECTED_NEXT_TXN_ID, 16));
    /* the artifact id is set correctly. */
    EXPECT_EQ(0, memcmp(&resp.artifact_id, &EXPECTED_ARTIFACT_ID, 16));
    /* the block id is set correctly. */
    EXPECT_EQ(0, memcmp(&resp.block_id, &EXPECTED_BLOCK_ID, 16));
    /* the serialized txn size is set correctly. */
    EXPECT_EQ(resp.txn_size, EXPECTED_SER_TXN_CERT_SIZE);
    /* the serialized transaction state is set correctly. */
    EXPECT_EQ(resp.txn_state, EXPECTED_TXN_STATE);
    /* the txn cert is set correctly. */
    ASSERT_EQ(EXPECTED_TXN_CERT_SIZE, resp.txn_cert.size);
    EXPECT_EQ(
        0,
        memcmp(
            resp.txn_cert.data, EXPECTED_TXN_CERT,
            EXPECTED_TXN_CERT_SIZE));

    /* clean up. */
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&resp);
    dispose((disposable_t*)&alloc_opts);
}
