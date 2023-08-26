/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_resp_transaction_submit.cpp
 *
 * Unit tests for encoding the transaction submit response.
 *
 * \copyright 2020-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_encode_resp_transaction_submit);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_check)
{
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* this method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_resp_transaction_submit(
                    nullptr, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_resp_transaction_submit(
                    &buffer, nullptr, EXPECTED_OFFSET, EXPECTED_STATUS));

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

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: null / zero out buffer. */
    buffer.data = nullptr; buffer.size = 0;

    /* this method should succeed. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_transaction_submit(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS));

    /* the buffer should not be null. */
    TEST_ASSERT(nullptr != buffer.data);
    TEST_ASSERT(3 * sizeof(uint32_t) == buffer.size);

    /* check the buffer values. */
    uint32_t* uarr = (uint32_t*)buffer.data;
    TEST_EXPECT(htonl(PROTOCOL_REQ_ID_TRANSACTION_SUBMIT) == uarr[0]);
    TEST_EXPECT(htonl(EXPECTED_STATUS) == uarr[1]);
    TEST_EXPECT(htonl(EXPECTED_OFFSET) == uarr[2]);

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
