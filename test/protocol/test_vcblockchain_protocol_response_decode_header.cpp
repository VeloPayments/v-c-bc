/**
 * \file test/protocol/test_vcblockchain_protocol_response_decode_header.cpp
 *
 * Unit tests for decoding the header of a response packet from the protocol.
 *
 * \copyright 2020-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/data.h>
#include <vpr/allocator/malloc_allocator.h>

TEST_SUITE(test_vcblockchain_protocol_response_decode_header);

/**
 * Test that vcblockchain_protocol_response_decode_header returns an invalid
 * argument error when any of the pointer arguments are NULL.
 */
TEST(parameter_checks)
{
    uint32_t request_id, offset, status;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a dummy buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&buffer, &alloc_opts, 32));

    /* passing a NULL for any of the arguments should fail. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_response_decode_header(
                    nullptr, &offset, &status, &buffer));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_response_decode_header(
                    &request_id, nullptr, &status, &buffer));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_response_decode_header(
                    &request_id, &offset, nullptr, &buffer));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_response_decode_header(
                    &request_id, &offset, &status, nullptr));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If the response buffer is too small, this an error is returned.
 */
TEST(buffer_size_check)
{
    uint32_t request_id, offset, status;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a dummy buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&buffer, &alloc_opts, 5));

    /* the buffer has to be at least 12 bytes in size. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_PROTOCOL_UNEXPECTED_PAYLOAD_SIZE
            == vcblockchain_protocol_response_decode_header(
                    &request_id, &offset, &status, &buffer));

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * We can parse a response header from the protocol.
 */
TEST(happy_path)
{
    uint32_t EXPECTED_REQUEST_ID = PROTOCOL_REQ_ID_BLOCK_ID_GET_PREV;
    uint32_t EXPECTED_OFFSET = 31;
    uint32_t EXPECTED_STATUS = 47;
    uint32_t request_id, offset, status;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a dummy buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&buffer, &alloc_opts, 3 * sizeof(uint32_t)));

    /* set up the buffer. */
    uint32_t* u32buf = (uint32_t*)buffer.data;
    u32buf[0] = htonl(EXPECTED_REQUEST_ID);
    u32buf[1] = htonl(EXPECTED_STATUS);
    u32buf[2] = htonl(EXPECTED_OFFSET);

    /* preconditions: header values are 0. */
    request_id = offset = status = 0;

    /* decoding the header should succeed. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_response_decode_header(
                    &request_id, &offset, &status, &buffer));

    /* postcondition: header values are set as expected. */
    TEST_EXPECT(EXPECTED_REQUEST_ID == request_id);
    TEST_EXPECT(EXPECTED_OFFSET == offset);
    TEST_EXPECT(EXPECTED_STATUS == status);

    /* cleanup. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
