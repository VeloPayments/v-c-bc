/**
 * \file test/protocol/test_vcblockchain_protocol_decode_resp_handshake_ack.cpp
 *
 * Unit tests for decoding the response portion of the handshake ack.
 *
 * \copyright 2020-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <minunit/minunit.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_decode_resp_handshake_ack);

/**
 * Test the basics of the decoding.
 */
TEST(basics)
{
    allocator_options_t alloc_opts;
    const uint32_t EXPECTED_OFFSET = 81;
    const uint32_t EXPECTED_STATUS = 6;
    vccrypt_buffer_t out;
    protocol_resp_handshake_ack resp;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* encoding the handshake ack response should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_handshake_ack(
                    &out, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS));

    /* decoding the handshake ack response should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vcblockchain_protocol_decode_resp_handshake_ack(
                    &resp, out.data, out.size));

    /* the request id should match what we expect. */
    TEST_EXPECT(PROTOCOL_REQ_ID_HANDSHAKE_ACKNOWLEDGE == resp.request_id);

    /* the offset should match. */
    TEST_EXPECT(EXPECTED_OFFSET == resp.offset);

    /* the status should match. */
    TEST_EXPECT(EXPECTED_STATUS == resp.status);

    /* clean up. */
    dispose((disposable_t*)&resp);
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&alloc_opts);
}
