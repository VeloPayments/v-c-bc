/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_req_handshake_request.cpp
 *
 * Unit tests for decoding the request portion of the handshake request.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

/**
 * Test the basics of the decoding.
 */
TEST(test_vcblockchain_protocol_decode_req_handshake_request, basics)
{
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vpr_uuid client_id = { .data = {
        0x6e, 0x48, 0xf1, 0x40, 0x6d, 0xbf, 0x4e, 0x8d,
        0xba, 0x0b, 0xf3, 0xcd, 0xba, 0x7b, 0x0c, 0xa8 } };
    vccrypt_buffer_t client_key_nonce;
    vccrypt_buffer_t client_challenge_nonce;
    vccrypt_buffer_t out;
    const uint32_t EXPECTED_OFFSET = 17;
    protocol_req_handshake_request req;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the crypto suite. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create a buffer for holding the key nonce. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &client_key_nonce));
    /* set the key nonce value. */
    memset(client_key_nonce.data, 0xFE, client_key_nonce.size);

    /* create a buffer for holding the challenge nonce. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &client_challenge_nonce));
    /* set the challenge nonce. */
    memset(client_challenge_nonce.data, 0xEC, client_challenge_nonce.size);

    /* encoding the handshake request should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_handshake_request(
            &out, &suite, EXPECTED_OFFSET, &client_id, &client_key_nonce,
            &client_challenge_nonce));

    /* decoding the handshake request should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vcblockchain_protocol_decode_req_handshake_request(
            &req, &suite, out.data, out.size));

    /* the request id should match what we expect. */
    EXPECT_EQ(PROTOCOL_REQ_ID_HANDSHAKE_INITIATE, req.request_id);

    /* the offset should match. */
    EXPECT_EQ(EXPECTED_OFFSET, req.offset);

    /* the protocol version should match what we expect. */
    EXPECT_EQ(PROTOCOL_VERSION_0_1_DEMO, req.protocol_version);

    /* the crypto suite should match what we expect. */
    EXPECT_EQ(VCCRYPT_SUITE_VELO_V1, req.crypto_suite);

    /* the client id should match. */
    EXPECT_EQ(0, memcmp(&client_id, &req.client_id, sizeof(client_id)));

    /* the key nonce should match. */
    EXPECT_EQ(client_key_nonce.size, req.client_key_nonce.size);
    EXPECT_EQ(
        0,
        memcmp(
            client_key_nonce.data, req.client_key_nonce.data,
            client_key_nonce.size));

    /* the challenge nonce should match. */
    EXPECT_EQ(client_challenge_nonce.size, req.client_challenge_nonce.size);
    EXPECT_EQ(
        0,
        memcmp(
            client_challenge_nonce.data, req.client_challenge_nonce.data,
            client_challenge_nonce.size));

    /* clean up. */
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&client_key_nonce);
    dispose((disposable_t*)&client_challenge_nonce);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
