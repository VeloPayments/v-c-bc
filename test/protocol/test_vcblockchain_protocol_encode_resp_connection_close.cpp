/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_resp_connection_close.cpp
 *
 * Unit tests for encoding the connection close response.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
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
TEST(test_vcblockchain_protocol_encode_resp_connection_close, parameters)
{
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* this method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_connection_close(
            nullptr, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_connection_close(
            &buffer, nullptr, EXPECTED_OFFSET, EXPECTED_STATUS));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/* This method should encode the response message. */
TEST(test_vcblockchain_protocol_encode_resp_connection_close, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: buffer is nulled out. */
    buffer.data = nullptr; buffer.size = 0;

    /* this method should succeed. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_resp_connection_close(
            &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS));

    /* the buffer should not be null. */
    ASSERT_NE(nullptr, buffer.data);
    ASSERT_EQ(3 * sizeof(uint32_t), buffer.size);

    /* check the integer values. */
    uint32_t* uarr = (uint32_t*)buffer.data;
    EXPECT_EQ(htonl(PROTOCOL_REQ_ID_CLOSE), uarr[0]);
    EXPECT_EQ(htonl(EXPECTED_STATUS), uarr[1]);
    EXPECT_EQ(htonl(EXPECTED_OFFSET), uarr[2]);

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}