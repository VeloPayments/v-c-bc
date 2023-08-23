/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_req_assert_latest_block_id_cancel.cpp
 *
 * Unit tests for decoding the latest block id assertion cancel request.
 *
 * \copyright 2022-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_decode_req_assert_latest_block_id_cancel);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_check)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_assert_latest_block_id_cancel req;

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_assert_latest_block_id_cancel(
                    nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_assert_latest_block_id_cancel(
                    &req, nullptr, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method should verify the payload size.
 */
TEST(payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_assert_latest_block_id_cancel req;

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_assert_latest_block_id_cancel(
                    &req, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method can decode a properly encoded request message.
 */
TEST(happy_path)
{
    const uint32_t EXPECTED_OFFSET = 21;
    allocator_options_t alloc_opts;
    protocol_req_assert_latest_block_id_cancel req;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* we can encode a message. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_req_assert_latest_block_id_cancel(
                    &buffer, &alloc_opts, EXPECTED_OFFSET));

    /* precondition: the request buffer is zeroed out. */
    memset(&req, 0, sizeof(req));

    /* We can decode this message. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_decode_req_assert_latest_block_id_cancel(
                    &req, buffer.data, buffer.size));

    /* the request id is set correctly. */
    TEST_EXPECT(
        PROTOCOL_REQ_ID_ASSERT_LATEST_BLOCK_ID_CANCEL == req.request_id);
    /* the offset is set correctly. */
    TEST_EXPECT(EXPECTED_OFFSET == req.offset);

    /* clean up. */
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
