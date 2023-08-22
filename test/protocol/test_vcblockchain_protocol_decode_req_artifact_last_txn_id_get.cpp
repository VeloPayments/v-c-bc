/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_req_artifact_last_txn_id_get.cpp
 *
 * Unit tests for decoding the artifact last txn id get request.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

/* DISABLED GTEST */
#if 0

using namespace std;

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(
    test_vcblockchain_protocol_decode_req_artifact_last_txn_id_get,
    parameter_check)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_artifact_last_txn_id_get req;

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_artifact_last_txn_id_get(
            nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_artifact_last_txn_id_get(
            &req, nullptr, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method should verify the payload size.
 */
TEST(
    test_vcblockchain_protocol_decode_req_artifact_last_txn_id_get,
    payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_artifact_last_txn_id_get req;

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_artifact_last_txn_id_get(
            &req, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method can decode a properly encoded request message.
 */
TEST(
    test_vcblockchain_protocol_decode_req_artifact_last_txn_id_get, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 21;
    const vpr_uuid EXPECTED_ARTIFACT_ID = { .data = {
        0x39, 0x22, 0xcc, 0xac, 0x30, 0xd6, 0x49, 0xe0,
        0xb8, 0x0a, 0x91, 0x2b, 0xd6, 0xff, 0x6f, 0x20 } };
    allocator_options_t alloc_opts;
    protocol_req_artifact_last_txn_id_get req;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* we can encode a message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_artifact_last_txn_id_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &EXPECTED_ARTIFACT_ID));

    /* precondition: the request buffer is zeroed out. */
    memset(&req, 0, sizeof(req));

    /* We can decode this message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_decode_req_artifact_last_txn_id_get(
            &req, buffer.data, buffer.size));

    /* the request id is set correctly. */
    EXPECT_EQ(PROTOCOL_REQ_ID_ARTIFACT_LAST_TXN_BY_ID_GET, req.request_id);
    /* the offset is set correctly. */
    EXPECT_EQ(EXPECTED_OFFSET, req.offset);
    /* the block id is set correctly. */
    EXPECT_EQ(0, memcmp(&req.artifact_id, &EXPECTED_ARTIFACT_ID, 16));

    /* clean up. */
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
#endif
