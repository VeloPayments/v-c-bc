/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_req_extended_api.cpp
 *
 * Unit tests for encoding an extended API request.
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

TEST_SUITE(test_vcblockchain_protocol_encode_req_extended_api);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_checks)
{
    const uint32_t EXPECTED_OFFSET = 113;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t request_body;
    vpr_uuid entity_id = { .data = {
        0xa6, 0xb7, 0x61, 0xff, 0x4a, 0xa1, 0x45, 0xb9,
        0xa9, 0x28, 0x80, 0x07, 0x91, 0x76, 0xee, 0xf6 } };
    vpr_uuid verb_id = { .data = {
        0x5f, 0x4f, 0x24, 0x05, 0xf6, 0xfb, 0x44, 0xc0,
        0xa7, 0x08, 0x8a, 0xdf, 0x73, 0x3a, 0x95, 0x57 } };

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_extended_api(
                    nullptr, &alloc_opts, EXPECTED_OFFSET, &entity_id, &verb_id,
                    &request_body));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_extended_api(
                    &buffer, nullptr, EXPECTED_OFFSET, &entity_id, &verb_id,
                    &request_body));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_extended_api(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, nullptr, &verb_id,
                    &request_body));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_extended_api(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, &entity_id, nullptr,
                    &request_body));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_req_extended_api(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, &entity_id, &verb_id,
                    nullptr));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If valid parameters are provided, this method encodes a request message.
 */
TEST(happy_path)
{
    const uint32_t EXPECTED_OFFSET = 113;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t request_body;
    vpr_uuid entity_id = { .data = {
        0xa6, 0xb7, 0x61, 0xff, 0x4a, 0xa1, 0x45, 0xb9,
        0xa9, 0x28, 0x80, 0x07, 0x91, 0x76, 0xee, 0xf6 } };
    vpr_uuid verb_id = { .data = {
        0x5f, 0x4f, 0x24, 0x05, 0xf6, 0xfb, 0x44, 0xc0,
        0xa7, 0x08, 0x8a, 0xdf, 0x73, 0x3a, 0x95, 0x57 } };

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a dummy buffer for the request body. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&request_body, &alloc_opts, 32));
    memset(request_body.data, 0xfc, request_body.size);

    /* precondition: set the buffer to NULL / 0. */
    buffer.data = nullptr; buffer.size = 0;

    /* This method encodes the request. */
    TEST_EXPECT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_req_extended_api(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, &entity_id, &verb_id,
                    &request_body));

    /* compute the message size. */
    size_t message_size =
        2 * sizeof(uint32_t) + sizeof(entity_id) + sizeof(verb_id)
        + request_body.size;

    /* the buffer has been initialized. */
    TEST_ASSERT(nullptr != buffer.data);
    TEST_ASSERT(message_size == buffer.size);

    /* verify that the request id and offset are set correctly. */
    const uint32_t* u32arr = (const uint32_t*)buffer.data;
    TEST_EXPECT(PROTOCOL_REQ_ID_EXTENDED_API_SENDRECV == ntohl(u32arr[0]));
    TEST_EXPECT(EXPECTED_OFFSET == ntohl(u32arr[1]));

    /* verify that the UUIDs are set correctly. */
    const uint8_t* u8arr = (const uint8_t*)(u32arr + 2);
    TEST_EXPECT(0 == memcmp(u8arr, &entity_id, sizeof(entity_id)));
    u8arr += sizeof(entity_id);
    TEST_EXPECT(0 == memcmp(u8arr, &verb_id, sizeof(verb_id)));
    u8arr += sizeof(verb_id);

    /* verify that the request body is set correctly. */
    TEST_EXPECT(0 == memcmp(u8arr, request_body.data, request_body.size));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&request_body);
    dispose((disposable_t*)&alloc_opts);
}
