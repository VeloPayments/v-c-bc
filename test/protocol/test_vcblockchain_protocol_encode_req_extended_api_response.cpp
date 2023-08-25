/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_req_extended_api_response.cpp
 *
 * Unit tests for encoding an extended API response request.
 *
 * \copyright 2022-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_encode_req_extended_api_response);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_checks)
{
    const uint64_t EXPECTED_OFFSET = 71;
    const uint32_t EXPECTED_STATUS = 9;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t response_body;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_extended_api_response(
                    nullptr, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &response_body));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_extended_api_response(
                    &buffer, nullptr, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &response_body));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_extended_api_response(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    nullptr));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If valid parameters are provided, this method encodes a request response
 * message.
 */
TEST(happy_path)
{
    const uint64_t EXPECTED_OFFSET = 71;
    const uint32_t EXPECTED_STATUS = 9;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t response_body;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create dummy response body. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&response_body, &alloc_opts, 32));
    memset(response_body.data, 0x12, response_body.size);

    /* precondition: clear the output buffer. */
    memset(&buffer, 0, sizeof(buffer));

    /* We should be able to encode this message. */
    TEST_EXPECT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_req_extended_api_response(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &response_body));

    /* compute the message size. */
    size_t message_size =
        sizeof(uint32_t)
      + sizeof(EXPECTED_OFFSET)
      + sizeof(EXPECTED_STATUS)
      + response_body.size;

    /* the buffer has been initialized. */
    TEST_ASSERT(nullptr != buffer.data);
    TEST_ASSERT(message_size == buffer.size);

    /* make working with this buffer easier. */
    const uint8_t* barr = (const uint8_t*)buffer.data;

    /* verify the request id. */
    uint32_t net_request_id;
    memcpy(&net_request_id, barr, sizeof(net_request_id));
    barr += sizeof(net_request_id);
    TEST_EXPECT(PROTOCOL_REQ_ID_EXTENDED_API_SENDRESP == ntohl(net_request_id));

    /* verify the offset. */
    uint64_t net_offset;
    memcpy(&net_offset, barr, sizeof(net_offset));
    barr += sizeof(net_offset);
    TEST_EXPECT(EXPECTED_OFFSET == ntohll(net_offset));

    /* verify the status. */
    uint32_t net_status;
    memcpy(&net_status, barr, sizeof(net_status));
    barr += sizeof(net_status);
    TEST_EXPECT(EXPECTED_STATUS == ntohl(net_status));

    /* verify the response body. */
    TEST_EXPECT(0 == memcmp(response_body.data, barr, response_body.size));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&response_body);
    dispose((disposable_t*)&alloc_opts);
}
