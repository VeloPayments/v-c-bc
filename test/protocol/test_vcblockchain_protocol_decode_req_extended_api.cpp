/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_req_extended_api.cpp
 *
 * Unit tests for decoding an extended API request.
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
TEST(test_vcblockchain_protocol_decode_req_extended_api, parameter_checks)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_extended_api req;
    allocator_options_t alloc_opts;

    /* initialize the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_extended_api(
            nullptr, &alloc_opts, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_extended_api(
            &req, nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_extended_api(
            &req, &alloc_opts, nullptr, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method should verify the payload size.
 */
TEST(test_vcblockchain_protocol_decode_req_extended_api, payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_extended_api req;
    allocator_options_t alloc_opts;

    /* initialize the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method verifies the payload size. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_extended_api(
            &req, &alloc_opts, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method can decode a properly encoded request message.
 */
TEST(test_vcblockchain_protocol_decode_req_extended_api, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 77;
    allocator_options_t alloc_opts;
    protocol_req_extended_api req;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t request_body;
    const vpr_uuid entity_id = { .data = {
        0x4a, 0x2f, 0xb4, 0x23, 0x32, 0x55, 0x45, 0x6d,
        0xbf, 0x0c, 0x1e, 0xdf, 0xd6, 0x39, 0x4c, 0x12 } };
    const vpr_uuid verb_id = { .data = {
        0xb8, 0x91, 0x5d, 0xf1, 0x3d, 0xf3, 0x45, 0x3f,
        0x82, 0xa7, 0xc8, 0x38, 0xd5, 0x91, 0x45, 0xf3 } };

    /* initialize the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a dummy request body. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&request_body, &alloc_opts, 32));
    memset(request_body.data, 32, request_body.size);

    /* we can encode a message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_extended_api(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &entity_id, &verb_id,
            &request_body));

    /* precondition: the request buffer is zeroed out. */
    memset(&req, 0, sizeof(req));

    /* we can decode this message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_decode_req_extended_api(
            &req, &alloc_opts, buffer.data, buffer.size));

    /* the request id is set correctly. */
    EXPECT_EQ(PROTOCOL_REQ_ID_EXTENDED_API_SENDRECV, req.request_id);
    /* the offset is set correctly. */
    EXPECT_EQ(EXPECTED_OFFSET, req.offset);
    /* the entity id is set correctly. */
    EXPECT_EQ(0, memcmp(&req.entity_id, &entity_id, sizeof(entity_id)));
    /* the verb id is set correctly. */
    EXPECT_EQ(0, memcmp(&req.verb_id, &verb_id, sizeof(verb_id)));
    /* the request body is set correctly. */
    ASSERT_NE(nullptr, req.request_body.data);
    ASSERT_EQ(request_body.size, req.request_body.size);
    EXPECT_EQ(
        0, memcmp(req.request_body.data, request_body.data, request_body.size));

    /* clean up. */
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&request_body);
    dispose((disposable_t*)&alloc_opts);
}
