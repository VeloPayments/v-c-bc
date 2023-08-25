/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_req_status_get.cpp
 *
 * Unit tests for encoding the status get request.
 *
 * \copyright 2021-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_encode_req_status_get);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_check)
{
    const uint32_t EXPECTED_OFFSET = 97;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_status_get(
                    nullptr, &alloc_opts, EXPECTED_OFFSET));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_status_get(
                    &buffer, nullptr, EXPECTED_OFFSET));

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

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: set the buffer to null / 0. */
    buffer.data = nullptr; buffer.size = 0;

    /* This method encodes the request. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_req_status_get(
                    &buffer, &alloc_opts, EXPECTED_OFFSET));

    /* compute the message size. */
    size_t message_size = 2 * sizeof(uint32_t);

    /* the buffer has been initialized. */
    TEST_ASSERT(nullptr != buffer.data);
    TEST_ASSERT(message_size == buffer.size);

    /* verify that the request id and offset is set correctly. */
    const uint32_t* u32arr = (const uint32_t*)buffer.data;
    TEST_EXPECT(htonl(PROTOCOL_REQ_ID_STATUS_GET) == u32arr[0]);
    TEST_EXPECT(htonl(EXPECTED_OFFSET) == u32arr[1]);

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
