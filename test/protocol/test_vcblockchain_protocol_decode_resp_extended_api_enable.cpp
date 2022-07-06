/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_resp_extended_api_enable.cpp
 *
 * Unit tests for decoding an extended api enable response.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(test_vcblockchain_protocol_decode_resp_extended_api_enable, parameters)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_resp_extended_api_enable resp;

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_resp_extended_api_enable(
            nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_resp_extended_api_enable(
            &resp, nullptr, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method should check the payload size to make sure it is correct.
 */
TEST(test_vcblockchain_protocol_decode_resp_extended_api_enable, payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_resp_extended_api_enable resp;

    /* This method performs a payload size check. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_resp_extended_api_enable(
            &resp, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method can decode a properly encoded response message.
 */
TEST(test_vcblockchain_protocol_decode_resp_extended_api_enable, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 12;
    const uint32_t EXPECTED_STATUS = 77;
    allocator_options_t alloc_opts;
    protocol_resp_extended_api_enable resp;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* we can encode a message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_resp_extended_api_enable(
            &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS));

    /* precondition: the response buffer is zeroed out. */
    memset(&resp, 0, sizeof(resp));

    /* we can decode this message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_decode_resp_extended_api_enable(
            &resp, buffer.data, buffer.size));

    /* the request id is set correctly. */
    EXPECT_EQ(PROTOCOL_REQ_ID_EXTENDED_API_ENABLE, resp.request_id);
    /* the offset is set correctly. */
    EXPECT_EQ(EXPECTED_OFFSET, resp.offset);
    /* the status is set correctly. */
    EXPECT_EQ(EXPECTED_STATUS, resp.status);

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&resp);
    dispose((disposable_t*)&alloc_opts);
}
