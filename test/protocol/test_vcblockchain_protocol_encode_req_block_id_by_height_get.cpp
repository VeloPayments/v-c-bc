/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_req_block_id_by_height_get.cpp
 *
 * Unit tests for encoding the block id by height get request.
 *
 * \copyright 2021-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <minunit/minunit.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_encode_req_block_id_by_height_get);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_check)
{
    const uint32_t EXPECTED_OFFSET = 97;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    const uint64_t EXPECTED_HEIGHT = 0x0123456789abcdef;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_block_id_by_height_get(
                    nullptr, &alloc_opts, EXPECTED_OFFSET, EXPECTED_HEIGHT));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_block_id_by_height_get(
                    &buffer, nullptr, EXPECTED_OFFSET, EXPECTED_HEIGHT));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If valid parameters are provided, this method encodes a request message.
 */
TEST(happy_path)
{
    const uint32_t EXPECTED_OFFSET = 97;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    const uint64_t EXPECTED_HEIGHT = 0x0123456789abcdef;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: set the buffer to null / 0. */
    buffer.data = nullptr; buffer.size = 0;

    /* This method performs null checks on pointer parameters. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_req_block_id_by_height_get(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_HEIGHT));

    /* compute the message size. */
    size_t message_size = 2 * sizeof(uint32_t) + 8;

    /* the buffer has been initialized. */
    TEST_ASSERT(nullptr != buffer.data);
    TEST_ASSERT(message_size == buffer.size);

    /* verify that the request id and offset is set correctly. */
    const uint32_t* u32arr = (const uint32_t*)buffer.data;
    TEST_EXPECT(htonl(PROTOCOL_REQ_ID_BLOCK_ID_BY_HEIGHT_GET) == u32arr[0]);
    TEST_EXPECT(htonl(EXPECTED_OFFSET) == u32arr[1]);

    /* verify that the block id is set correctly. */
    const uint64_t* height = (const uint64_t*)(u32arr + 2);
    TEST_EXPECT(htonll(*height) == EXPECTED_HEIGHT);

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
