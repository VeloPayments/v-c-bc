/**
 * \file test/protocol/test_vcblockchain_protocol_encode_req_handshake_ack.cpp
 *
 * Unit tests for encoding the request portion of the handshake ack request.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

/**
 * Test the basics of the encoding.
 */
TEST(test_vcblockchain_protocol_encode_req_handshake_ack, basics)
{
    const uint8_t EXPECTED_MAC[32] = {
        0xef, 0xeb, 0xbe, 0x57, 0x8c, 0x6e, 0x47, 0x4d,
        0xa4, 0x68, 0x16, 0xf4, 0xa0, 0x08, 0x91, 0xe9,
        0xf5, 0xc6, 0x12, 0xb5, 0x36, 0x21, 0x4c, 0x1f,
        0xb6, 0x33, 0xda, 0x9e, 0x7b, 0x40, 0x8c, 0x90 };
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vccrypt_buffer_t mac;
    vccrypt_buffer_t out;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the crypto suite. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create a buffer for holding the expected mac. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &mac, &alloc_opts, sizeof(EXPECTED_MAC)));
    /* set the mac value. */
    memcpy(mac.data, EXPECTED_MAC, sizeof(EXPECTED_MAC));

    /* PRECONDITION: output should have a null data and 0 size. */
    out.data = nullptr;
    out.size = 0U;

    /* encoding the handshake ack request should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_handshake_ack(&out, &suite, &mac));

    /* the out data and size should be set. */
    ASSERT_NE(nullptr, out.data);
    ASSERT_NE(0U, out.size);

    /* get a byte pointer to the output buffer. */
    const uint8_t* buf = (const uint8_t*)out.data;
    size_t size = out.size;

    /* the buffer should hold the mac. */
    ASSERT_EQ(size, mac.size);
    EXPECT_EQ(0, memcmp(buf, mac.data, mac.size));

    /* clean up. */
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&mac);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
