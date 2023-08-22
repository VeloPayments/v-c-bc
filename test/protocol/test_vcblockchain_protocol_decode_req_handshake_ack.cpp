/**
 * \file test/protocol/test_vcblockchain_protocol_decode_req_handshake_ack.cpp
 *
 * Unit tests for decoding the request portion of the handshake ack.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

/* DISABLED GTEST */
#if 0

using namespace std;

/**
 * Test the basics of the decoding.
 */
TEST(test_vcblockchain_protocol_decode_req_handshake_ack, basics)
{
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    const uint8_t EXPECTED_MAC[32] = {
        0x8a, 0x8c, 0xa0, 0x0f, 0xa3, 0xdd, 0x45, 0xd1,
        0xac, 0x2f, 0xdd, 0x93, 0x1c, 0xdd, 0xeb, 0x3e,
        0xdd, 0x06, 0x67, 0x57, 0x88, 0xba, 0x4b, 0xa9,
        0x92, 0x98, 0x61, 0x13, 0xe7, 0xa2, 0xe2, 0x64 };
    vccrypt_buffer_t mac;
    vccrypt_buffer_t out;
    protocol_req_handshake_ack req;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the crypto suite. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create a buffer for holding the mac. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &mac, &alloc_opts, sizeof(EXPECTED_MAC)));
    /* set the mac value. */
    ASSERT_EQ(sizeof(EXPECTED_MAC), mac.size);
    memcpy(mac.data, EXPECTED_MAC, mac.size);

    /* encoding the handshake ack should succeed. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_handshake_ack(
            &out, &suite, &mac));

    /* decoding the handshake ack should succeed. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_decode_req_handshake_ack(
            &req, &suite, out.data, out.size));

    /* the mac should match. */
    ASSERT_EQ(sizeof(EXPECTED_MAC), req.digest.size);
    EXPECT_EQ(0, memcmp(req.digest.data, EXPECTED_MAC, req.digest.size));

    /* clean up. */
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&mac);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
#endif
