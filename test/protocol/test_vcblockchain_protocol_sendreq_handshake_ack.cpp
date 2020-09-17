/**
 * \file test/protocol/test_vcblockchain_protocol_sendreq_handshake_ack.cpp
 *
 * Unit tests for writing the handshake ack to a server socket.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <memory>
#include <queue>
#include <vcblockchain/protocol.h>
#include <vpr/allocator/malloc_allocator.h>

#include "../ssock/dummy_ssock.h"

using namespace std;

/**
 * Test the happy path.
 */
TEST(test_vcblockchain_protocol_sendreq_handshake_ack, happy_path)
{
    ssock sock;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    const uint64_t EXPECTED_CLIENT_IV = 2;
    const uint64_t EXPECTED_SERVER_IV_AFTER_SENDREQ = 1;
    const uint64_t EXPECTED_SERVER_IV_AFTER_RECVRESP = 2;
    const uint8_t SHARED_SECRET[32] = {
        0x16, 0xac, 0x42, 0x3e, 0x91, 0x9d, 0x40, 0x6b,
        0xa6, 0x1c, 0x9a, 0x92, 0x70, 0x62, 0x2d, 0xe6,
        0x44, 0x55, 0xbd, 0xa3, 0xb3, 0x22, 0x48, 0xb0,
        0x8f, 0xd7, 0x58, 0xaf, 0x15, 0x71, 0x99, 0xf1 };
    const uint8_t CHALLENGE_NONCE[32] = {
        0xcf, 0xcd, 0xb9, 0x6f, 0xf8, 0xec, 0x4d, 0xca,
        0xa8, 0x26, 0xae, 0x24, 0x50, 0x65, 0x27, 0xdb,
        0xc2, 0x97, 0x7d, 0x38, 0xaf, 0x0f, 0x45, 0x34,
        0x9b, 0x83, 0x0c, 0x85, 0x9b, 0xd7, 0x50, 0x1a };
    vccrypt_buffer_t shared_secret;
    vccrypt_buffer_t server_challenge_nonce;
    vccrypt_mac_context_t mac;
    vccrypt_buffer_t digest;
    vccrypt_buffer_t out;
    uint64_t client_iv, server_iv;
    queue<uint8_t> stream;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the crypto suite. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create the shared secret buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &suite, &shared_secret));
    ASSERT_EQ(sizeof(SHARED_SECRET), shared_secret.size);
    memcpy(shared_secret.data, SHARED_SECRET, shared_secret.size);

    /* create the nonce buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &server_challenge_nonce));
    ASSERT_EQ(sizeof(CHALLENGE_NONCE), server_challenge_nonce.size);
    memcpy(server_challenge_nonce.data, CHALLENGE_NONCE,
           server_challenge_nonce.size);

    /* create the digest buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_mac_authentication_code(
            &suite, &digest, true));

    /* create the mac instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_mac_short_init(&suite, &mac, &shared_secret));

    /* add the challenge bytes to the mac. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mac_digest(
            &mac, (const uint8_t*)server_challenge_nonce.data,
            server_challenge_nonce.size));

    /* finalize the mac. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mac_finalize(&mac, &digest));

    /* create the dummy socket. */
    ASSERT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_ssock_init(
            &sock,
            [&](ssock*, void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_READ;
            },
            [&](ssock*, const void* val, size_t* size) -> int {
                const uint8_t* bval = (const uint8_t*)val;

                for (size_t i = 0; i < *size; ++i)
                    stream.push(bval[i]);

                return VCBLOCKCHAIN_STATUS_SUCCESS;
            }));

    /* PRECONDITIONS - set the IVs to 0. */
    client_iv = server_iv = 0;

    /* writing the handshake ack should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vcblockchain_protocol_sendreq_handshake_ack(
            &sock, &suite, &client_iv, &server_iv, &shared_secret,
            &server_challenge_nonce));

    /* the nonces should be set. */
    EXPECT_EQ(EXPECTED_CLIENT_IV, client_iv);
    EXPECT_EQ(EXPECTED_SERVER_IV_AFTER_SENDREQ, server_iv);

    /* dispose the old socket. */
    dispose((disposable_t*)&sock);

    /* initialize the socket for reading. */
    ASSERT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_ssock_init(
            &sock,
            [&](ssock*, void* val, size_t* size) -> int {
                uint8_t* bval = (uint8_t*)val;

                if (stream.size() < *size)
                    return VCBLOCKCHAIN_ERROR_SSOCK_READ;

                for (size_t i = 0; i < *size; ++i)
                {
                    bval[i] = stream.front();
                    stream.pop();
                }

                return VCBLOCKCHAIN_STATUS_SUCCESS;
            },
            [&](ssock*, const void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
            }));

    /* reading a response should succeed. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_recvresp(
            &sock, &suite, &server_iv, &shared_secret, &out));

    /* the server iv should be correct. */
    EXPECT_EQ(EXPECTED_SERVER_IV_AFTER_RECVRESP, server_iv);

    /* the digest should match. */
    ASSERT_EQ(digest.size, out.size);
    EXPECT_EQ(0, memcmp(digest.data, out.data, digest.size));

    /* clean up. */
    dispose((disposable_t*)&sock);
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&shared_secret);
    dispose((disposable_t*)&server_challenge_nonce);
    dispose((disposable_t*)&digest);
    dispose((disposable_t*)&mac);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
