/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_req_latest_block_id.cpp
 *
 * Unit tests for encoding the latest block id assertion request.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(
    test_vcblockchain_protocol_encode_req_assert_latest_block_id,
    parameter_check)
{
    const uint32_t EXPECTED_OFFSET = 97;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vpr_uuid latest_block_id = { .data = {
        0x89, 0xf5, 0xcf, 0x61, 0x21, 0x84, 0x48, 0xf9,
        0xa8, 0xd0, 0xbf, 0xf9, 0x76, 0xfa, 0x4d, 0xc9 } };

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_assert_latest_block_id(
            nullptr, &alloc_opts, EXPECTED_OFFSET, &latest_block_id));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_assert_latest_block_id(
            &buffer, nullptr, EXPECTED_OFFSET, &latest_block_id));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_assert_latest_block_id(
            &buffer, &alloc_opts, EXPECTED_OFFSET, nullptr));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If valid parameters are provided, this method encodes a request message.
 */
TEST(test_vcblockchain_protocol_encode_req_assert_latest_block_id, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 97;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vpr_uuid latest_block_id = { .data = {
        0x89, 0xf5, 0xcf, 0x61, 0x21, 0x84, 0x48, 0xf9,
        0xa8, 0xd0, 0xbf, 0xf9, 0x76, 0xfa, 0x4d, 0xc9 } };

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: set the buffer to null / 0. */
    buffer.data = nullptr; buffer.size = 0;

    /* This method encodes the request. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_assert_latest_block_id(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &latest_block_id));

    /* compute the message size. */
    size_t message_size = 2 * sizeof(uint32_t) + sizeof(latest_block_id);

    /* the buffer has been initialized. */
    ASSERT_NE(nullptr, buffer.data);
    ASSERT_EQ(message_size, buffer.size);

    /* verify that the request id and offset are set correctly. */
    const uint32_t* u32arr = (const uint32_t*)buffer.data;
    EXPECT_EQ(htonl(PROTOCOL_REQ_ID_ASSERT_LATEST_BLOCK_ID), u32arr[0]);
    EXPECT_EQ(htonl(EXPECTED_OFFSET), u32arr[1]);

    /* verify that the latest block id has been encoded. */
    EXPECT_EQ(0, memcmp(&latest_block_id, u32arr + 2, sizeof(latest_block_id)));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
