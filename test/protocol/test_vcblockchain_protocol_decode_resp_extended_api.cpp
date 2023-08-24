/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_resp_extended_api.cpp
 *
 * Unit tests for decoding an extended api response.
 *
 * \copyright 2022-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_decode_resp_extended_api);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_checks)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_resp_extended_api resp;
    allocator_options_t alloc_opts;

    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_extended_api(
                    nullptr, &alloc_opts, EXPECTED_PAYLOAD,
                    EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_extended_api(
                    &resp, nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_extended_api(
                    &resp, &alloc_opts, nullptr, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method should check the payload size to make sure it is correct.
 */
TEST(payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_resp_extended_api resp;
    allocator_options_t alloc_opts;

    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_extended_api(
                    &resp, &alloc_opts, EXPECTED_PAYLOAD,
                    EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method can decode a properly encoded response message.
 */
TEST(happy_path)
{
    const uint32_t EXPECTED_OFFSET = 12;
    const uint32_t EXPECTED_STATUS = 77;
    protocol_resp_extended_api resp;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t response_body;

    malloc_allocator_options_init(&alloc_opts);

    /* create a dummy response body. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&response_body, &alloc_opts, 32));
    memset(response_body.data, 0xde, response_body.size);

    /* we can encode a message. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_extended_api(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &response_body));

    /* precondition: the response buffer is zeroed out. */
    memset(&resp, 0, sizeof(resp));

    /* we can decode this message. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_decode_resp_extended_api(
                    &resp, &alloc_opts, buffer.data, buffer.size));

    /* the request id is set correctly. */
    TEST_EXPECT(PROTOCOL_REQ_ID_EXTENDED_API_SENDRECV == resp.request_id);
    /* the offset is set correctly. */
    TEST_EXPECT(EXPECTED_OFFSET == resp.offset);
    /* the status is set correctly. */
    TEST_EXPECT(EXPECTED_STATUS == resp.status);
    /* the response body is initialized. */
    TEST_ASSERT(nullptr != resp.response_body.data);
    TEST_ASSERT(response_body.size == resp.response_body.size);
    /* the response body is set correctly. */
    TEST_EXPECT(
        0
            == memcmp(
                    response_body.data, resp.response_body.data,
                    response_body.size));

    /* clean up. */
    dispose((disposable_t*)&resp);
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
