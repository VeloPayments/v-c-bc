/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_req_assert_latest_block_id.cpp
 *
 * Unit tests for decoding the latest block id assertion request.
 *
 * \copyright 2022-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_decode_req_assert_latest_block_id);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_check)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_assert_latest_block_id req;

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_assert_latest_block_id(
                    nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_assert_latest_block_id(
                    &req, nullptr, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method should verify the payload size.
 */
TEST(payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_assert_latest_block_id req;

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_assert_latest_block_id(
                    &req, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method can decode a properly encoded request message.
 */
TEST(happy_path)
{
    const uint32_t EXPECTED_OFFSET = 21;
    allocator_options_t alloc_opts;
    protocol_req_assert_latest_block_id req;
    vccrypt_buffer_t buffer;
    vpr_uuid latest_block_id = { .data = {
        0xd4, 0x6f, 0x91, 0x6a, 0xff, 0x14, 0x4a, 0xe0,
        0xa1, 0x8c, 0xe0, 0x8a, 0x0f, 0xd2, 0x66, 0x14 } };

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* we can encode a message. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_req_assert_latest_block_id(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, &latest_block_id));

    /* precondition: the request buffer is zeroed out. */
    memset(&req, 0, sizeof(req));

    /* We can decode this message. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_decode_req_assert_latest_block_id(
                    &req, buffer.data, buffer.size));

    /* the request id is set correctly. */
    TEST_EXPECT(PROTOCOL_REQ_ID_ASSERT_LATEST_BLOCK_ID == req.request_id);
    /* the offset is set correctly. */
    TEST_EXPECT(EXPECTED_OFFSET == req.offset);
    /* the latest block id is set correctly. */
    TEST_EXPECT(0 == memcmp(&latest_block_id, &req.latest_block_id, 16));

    /* clean up. */
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
