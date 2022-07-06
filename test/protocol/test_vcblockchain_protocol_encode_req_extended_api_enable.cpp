/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_req_extended_api_enable.cpp
 *
 * Unit tests for encoding an extended API enable request.
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
TEST(test_vcblockchain_protocol_encode_req_extended_api_enable, parameter_check)
{
    const uint32_t EXPECTED_OFFSET = 105;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_extended_api_enable(
            nullptr, &alloc_opts, EXPECTED_OFFSET));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_extended_api_enable(
            &buffer, nullptr, EXPECTED_OFFSET));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If valid parameters are provided, this method encodes a request message.
 */
TEST(test_vcblockchain_protocol_encode_req_extended_api_enable, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 105;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: set the buffer to NULL / 0. */
    buffer.data = nullptr; buffer.size = 0;

    /* This method encodes the request. */
    EXPECT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_extended_api_enable(
            &buffer, &alloc_opts, EXPECTED_OFFSET));

    /* compute the message size. */
    size_t message_size = 2 * sizeof(uint32_t);

    /* the buffer has been initialized. */
    ASSERT_NE(nullptr, buffer.data);
    ASSERT_EQ(message_size, buffer.size);

    /* verify that the request id and offset are set correctly. */
    const uint32_t* u32arr = (const uint32_t*)buffer.data;
    EXPECT_EQ(PROTOCOL_REQ_ID_EXTENDED_API_ENABLE, ntohl(u32arr[0]));
    EXPECT_EQ(EXPECTED_OFFSET, ntohl(u32arr[1]));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}