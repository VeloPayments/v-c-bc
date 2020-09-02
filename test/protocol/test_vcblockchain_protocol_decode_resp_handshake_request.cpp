/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_resp_handshake_request.cpp
 *
 * Unit tests for decoding the response portion of the handshake request.
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
TEST(test_vcblockchain_protocol_decode_resp_handshake_request, basics)
{
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vpr_uuid agent_id = { .data = {
        0x6e, 0x48, 0xf1, 0x40, 0x6d, 0xbf, 0x4e, 0x8d,
        0xba, 0x0b, 0xf3, 0xcd, 0xba, 0x7b, 0x0c, 0xa8 } };
    vccrypt_buffer_t server_public_key;
    vccrypt_buffer_t server_key_nonce;
    vccrypt_buffer_t server_challenge_nonce;
    vccrypt_buffer_t server_cr_hmac;
    vccrypt_buffer_t out;
    const uint32_t EXPECTED_OFFSET = 17;
    const uint32_t EXPECTED_STATUS = 0;
    protocol_resp_handshake_request resp;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the crypto suite. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create a buffer for holding the public key. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &suite, &server_public_key));
    /* set the public key value. */
    memset(server_public_key.data, 0xF1, server_public_key.size);

    /* create a buffer for holding the key nonce. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &server_key_nonce));
    /* set the key nonce value. */
    memset(server_key_nonce.data, 0xFE, server_key_nonce.size);

    /* create a buffer for holding the challenge nonce. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_auth_key_agreement_nonce(
            &suite, &server_challenge_nonce));
    /* set the challenge nonce. */
    memset(server_challenge_nonce.data, 0xEC, server_challenge_nonce.size);

    /* create a buffer for holding the cr hmac. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_mac_authentication_code(
            &suite, &server_cr_hmac, true));
    /* set the cr hmac. */
    memset(server_cr_hmac.data, 0xE1, server_cr_hmac.size);

    /* encoding the handshake response should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vcblockchain_protocol_encode_resp_handshake_request(
            &out, &suite, EXPECTED_OFFSET, EXPECTED_STATUS, &agent_id,
            &server_public_key, &server_key_nonce, &server_challenge_nonce,
            &server_cr_hmac));

    /* decoding the handshake request response should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vcblockchain_protocol_decode_resp_handshake_request(
            &resp, &suite, out.data, out.size));

    /* the request id should match what we expect. */
    EXPECT_EQ(PROTOCOL_REQ_ID_HANDSHAKE_INITIATE, resp.request_id);

    /* the offset should match. */
    EXPECT_EQ(EXPECTED_OFFSET, resp.offset);

    /* the status should match. */
    EXPECT_EQ(EXPECTED_STATUS, resp.status);

    /* the protocol version should match what we expect. */
    EXPECT_EQ(PROTOCOL_VERSION_0_1_DEMO, resp.protocol_version);

    /* the crypto suite should match what we expect. */
    EXPECT_EQ(VCCRYPT_SUITE_VELO_V1, resp.crypto_suite);

    /* the agent id should match. */
    EXPECT_EQ(0, memcmp(&agent_id, &resp.agent_id, sizeof(agent_id)));

    /* the public key should match. */
    ASSERT_TRUE(resp.server_public_key_set);
    EXPECT_EQ(server_public_key.size, resp.server_public_key.size);
    EXPECT_EQ(
        0,
        memcmp(
            server_public_key.data, resp.server_public_key.data,
            server_public_key.size));

    /* the key nonce should match. */
    ASSERT_TRUE(resp.server_key_nonce_set);
    EXPECT_EQ(server_key_nonce.size, resp.server_key_nonce.size);
    EXPECT_EQ(
        0,
        memcmp(
            server_key_nonce.data, resp.server_key_nonce.data,
            server_key_nonce.size));

    /* the challenge nonce should match. */
    ASSERT_TRUE(resp.server_challenge_nonce_set);
    EXPECT_EQ(server_challenge_nonce.size, resp.server_challenge_nonce.size);
    EXPECT_EQ(
        0,
        memcmp(
            server_challenge_nonce.data, resp.server_challenge_nonce.data,
            server_challenge_nonce.size));

    /* the cr hmac should match. */
    ASSERT_TRUE(resp.server_cr_hmac_set);
    EXPECT_EQ(server_cr_hmac.size, resp.server_cr_hmac.size);
    EXPECT_EQ(
        0,
        memcmp(
            server_cr_hmac.data, resp.server_cr_hmac.data,
            server_cr_hmac.size));

    /* clean up. */
    dispose((disposable_t*)&resp);
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&server_public_key);
    dispose((disposable_t*)&server_key_nonce);
    dispose((disposable_t*)&server_challenge_nonce);
    dispose((disposable_t*)&server_cr_hmac);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
