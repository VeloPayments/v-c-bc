/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_req_latest_block_id_get.cpp
 *
 * Unit tests for encoding the latest block id get request.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
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
TEST(test_vcblockchain_protocol_encode_req_latest_block_id_get, parameter_check)
{
    const uint32_t EXPECTED_OFFSET = 97;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_latest_block_id_get(
            nullptr, &alloc_opts, EXPECTED_OFFSET));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_latest_block_id_get(
            &buffer, nullptr, EXPECTED_OFFSET));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method creates a request buffer to send to the server.
 */
TEST(test_vcblockchain_protocol_encode_req_latest_block_id_get, basics)
{
    const uint32_t EXPECTED_OFFSET = 97;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: the buffer is unset. */
    buffer.data = nullptr; buffer.size = 0;

    /* Creating the request buffer should succeed. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_latest_block_id_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET));

    /* The buffer is not null and is sized appropriately. */
    ASSERT_NE(nullptr, buffer.data);
    ASSERT_EQ(2 * sizeof(uint32_t), buffer.size);

    /* the first value saved iv the buffer is the request id. */
    uint32_t* pbuf = (uint32_t*)buffer.data;
    EXPECT_EQ(htonl(PROTOCOL_REQ_ID_LATEST_BLOCK_ID_GET), pbuf[0]);

    /* the second value is the offset. */
    EXPECT_EQ(htonl(EXPECTED_OFFSET), pbuf[1]);

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
