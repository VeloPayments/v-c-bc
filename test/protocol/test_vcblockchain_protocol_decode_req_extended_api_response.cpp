/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_req_extended_api_response.cpp
 *
 * Unit tests for decoding an extended API response request.
 *
 * \copyright 2022-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_decode_req_extended_api_response);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_checks)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_extended_api_response req;
    allocator_options_t alloc_opts;

    /* initialize the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_extended_api_response(
                    nullptr, &alloc_opts, EXPECTED_PAYLOAD,
                    EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_extended_api_response(
                    &req, nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_extended_api_response(
                    &req, &alloc_opts, nullptr, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method should verify the payload size.
 */
TEST(payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_extended_api_response req;
    allocator_options_t alloc_opts;

    /* initialize the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_extended_api_response(
                    &req, &alloc_opts, EXPECTED_PAYLOAD,
                    EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method can decode a properly encoded request message.
 */
TEST(happy_path)
{
    const uint64_t EXPECTED_OFFSET = 122;
    const uint32_t EXPECTED_STATUS = 221;
    protocol_req_extended_api_response req;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t response_body;

    /* initialize the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* create dummy response body. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&response_body, &alloc_opts, 32));
    memset(response_body.data, 0x77, response_body.size);

    /* we should be able to encode this request */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_req_extended_api_response(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &response_body));

    /* precondition: zero out request struct. */
    memset(&req, 0, sizeof(req));

    /* We should be able to decode the encoded buffer. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_decode_req_extended_api_response(
                    &req, &alloc_opts, buffer.data, buffer.size));

    /* the request id is set correctly. */
    TEST_EXPECT(PROTOCOL_REQ_ID_EXTENDED_API_SENDRESP == req.request_id);
    /* the offset is set correctly. */
    TEST_EXPECT(EXPECTED_OFFSET == req.offset);
    /* the status is set correctly. */
    TEST_EXPECT(EXPECTED_STATUS == req.status);
    /* the response body is set correctly. */
    TEST_ASSERT(nullptr != req.response_body.data);
    TEST_ASSERT(response_body.size == req.response_body.size);
    TEST_EXPECT(
        0
            == memcmp(
                    req.response_body.data, response_body.data,
                    response_body.size));

    /* clean up. */
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&response_body);
    dispose((disposable_t*)&alloc_opts);
}
