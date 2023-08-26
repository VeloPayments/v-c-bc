/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_resp_generic.cpp
 *
 * Unit tests for encoding a generic response message.
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

TEST_SUITE(test_vcblockchain_protocol_encode_resp_generic);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameters)
{
    const uint32_t EXPECTED_REQUEST_ID = 5;
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    const uint8_t EXPECTED_PAYLOAD[] = { 1, 2, 3, 4 };
    const size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* this method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_resp_generic(
                    nullptr, &alloc_opts, EXPECTED_REQUEST_ID, EXPECTED_OFFSET,
                    EXPECTED_STATUS, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_resp_generic(
                    &buffer, nullptr, EXPECTED_REQUEST_ID, EXPECTED_OFFSET,
                    EXPECTED_STATUS, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/* This method should encode a response message with no payload. */
TEST(happy_path_no_payload)
{
    const uint32_t EXPECTED_METHOD_ID = 5;
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    const void* EXPECTED_PAYLOAD = nullptr;
    const size_t EXPECTED_PAYLOAD_SIZE = 0U;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: buffer is nulled out. */
    buffer.data = nullptr; buffer.size = 0;

    /* this method should succeed. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_generic(
                    &buffer, &alloc_opts, EXPECTED_METHOD_ID, EXPECTED_OFFSET,
                    EXPECTED_STATUS, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));

    /* the buffer should not be null. */
    TEST_ASSERT(nullptr != buffer.data);
    TEST_ASSERT(3 * sizeof(uint32_t) == buffer.size);

    /* check the integer values. */
    uint32_t* uarr = (uint32_t*)buffer.data;
    TEST_EXPECT(htonl(EXPECTED_METHOD_ID) == uarr[0]);
    TEST_EXPECT(htonl(EXPECTED_STATUS) == uarr[1]);
    TEST_EXPECT(htonl(EXPECTED_OFFSET) == uarr[2]);

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/* This method should encode a response message with a payload. */
TEST(happy_path_with_payload)
{
    const uint32_t EXPECTED_METHOD_ID = 5;
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    const uint8_t EXPECTED_PAYLOAD[] = { 5, 4, 3, 2, 1 };
    const size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: buffer is nulled out. */
    buffer.data = nullptr; buffer.size = 0;

    /* this method should succeed. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_generic(
                    &buffer, &alloc_opts, EXPECTED_METHOD_ID, EXPECTED_OFFSET,
                    EXPECTED_STATUS, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));

    /* the buffer should not be null. */
    TEST_ASSERT(nullptr != buffer.data);
    TEST_ASSERT(3 * sizeof(uint32_t) + EXPECTED_PAYLOAD_SIZE == buffer.size);

    /* check the integer values. */
    uint32_t* uarr = (uint32_t*)buffer.data;
    TEST_EXPECT(htonl(EXPECTED_METHOD_ID) == uarr[0]);
    TEST_EXPECT(htonl(EXPECTED_STATUS) == uarr[1]);
    TEST_EXPECT(htonl(EXPECTED_OFFSET) == uarr[2]);

    /* check the payload value. */
    TEST_EXPECT(0 == memcmp(EXPECTED_PAYLOAD, uarr + 3, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
