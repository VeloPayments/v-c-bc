/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_resp_extended_api.cpp
 *
 * Unit tests for encoding an extended api response.
 *
 * \copyright 2022-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_encode_resp_extended_api);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_checks)
{
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t response_body;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* this method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_resp_extended_api(
                    nullptr, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &response_body));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_resp_extended_api(
                    &buffer, nullptr, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &response_body));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_resp_extended_api(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    nullptr));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method should encode the response message.
 */
TEST(happy_path)
{
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t response_body;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a dummy buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&response_body, &alloc_opts, 32));
    memset(response_body.data, 0xde, response_body.size);

    /* precondition: buffer is nulled out. */
    buffer.data = nullptr; buffer.size = 0;

    /* this method should succeed. */
    TEST_EXPECT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_extended_api(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &response_body));

    /* the buffer should not be null. */
    TEST_ASSERT(nullptr != buffer.data);
    TEST_ASSERT(3 * sizeof(uint32_t) + response_body.size == buffer.size);

    /* check the integer values. */
    const uint32_t* uarr = (const uint32_t*)buffer.data;
    TEST_EXPECT(PROTOCOL_REQ_ID_EXTENDED_API_SENDRECV == ntohl(uarr[0]));
    TEST_EXPECT(EXPECTED_STATUS == ntohl(uarr[1]));
    TEST_EXPECT(EXPECTED_OFFSET == ntohl(uarr[2]));

    /* check the body. */
    TEST_EXPECT(0 == memcmp(uarr + 3, response_body.data, response_body.size));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&response_body);
    dispose((disposable_t*)&alloc_opts);
}
