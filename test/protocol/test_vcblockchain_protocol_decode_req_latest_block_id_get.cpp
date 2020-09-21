/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_req_latest_block_id_get.cpp
 *
 * Unit tests for decoding the latest block id get request.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(test_vcblockchain_protocol_decode_req_latest_block_id_get, parameter_check)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    allocator_options_t alloc_opts;
    protocol_req_latest_block_id_get req;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_latest_block_id_get(
            nullptr, &alloc_opts, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_latest_block_id_get(
            &req, nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_latest_block_id_get(
            &req, &alloc_opts, nullptr, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method checks the payload size to make sure it matches what it expects.
 */
TEST(test_vcblockchain_protocol_decode_req_latest_block_id_get, payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[5] = { 0x00, 0x01, 0x02, 0x03, 0x04 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    allocator_options_t alloc_opts;
    protocol_req_latest_block_id_get req;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs a payload size check. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_PAYLOAD_SIZE,
        vcblockchain_protocol_decode_req_latest_block_id_get(
            &req, &alloc_opts, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method can decode a properly encoded request message.
 */
TEST(test_vcblockchain_protocol_decode_req_latest_block_id_get, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 76;
    allocator_options_t alloc_opts;
    protocol_req_latest_block_id_get req;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* we can encode a message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_latest_block_id_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET));

    /* precondition: the request buffer is zeroed out. */
    memset(&req, 0, sizeof(req));

    /* we can decode this message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_decode_req_latest_block_id_get(
            &req, &alloc_opts, buffer.data, buffer.size));

    /* the request id is set correctly. */
    EXPECT_EQ(PROTOCOL_REQ_ID_LATEST_BLOCK_ID_GET, req.request_id);
    /* the offset is set correctly. */
    EXPECT_EQ(EXPECTED_OFFSET, req.offset);

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&alloc_opts);
}
