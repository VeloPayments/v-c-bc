/**
 * \file test/protocol/test_vcblockchain_protocol_recvresp_handshake_request.cpp
 *
 * Unit tests for receiving the handshake request from a server socket.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

#include "../ssock/dummy_ssock.h"

using namespace std;

/**
 * Test the happy path.
 */
TEST(test_vcblockchain_protocol_recvresp_handshake_request, happy_path)
{
    ssock sock;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vccrypt_prng_context_t prng;
    vccrypt_key_agreement_context_t cipher_key_agreement;
    vccrypt_mac_context_t mac;
    vpr_uuid EXPECTED_AGENT_ID = { .data = {
        0x75, 0xf7, 0x2b, 0x90, 0xd3, 0x01, 0x48, 0xf6,
        0xb5, 0x4f, 0xa1, 0x44, 0x59, 0x5c, 0x56, 0x7d } };
    vpr_uuid agent_id;
    const uint32_t EXPECTED_OFFSET = 17U, EXPECTED_STATUS = 0U;
    vccrypt_buffer_t server_pubkey;
    vccrypt_buffer_t server_privkey;
    vccrypt_buffer_t server_key_nonce;
    vccrypt_buffer_t server_challenge_nonce;
    vccrypt_buffer_t server_cr_hmac;
    vccrypt_buffer_t client_pubkey;
    vccrypt_buffer_t client_privkey;
    vccrypt_buffer_t client_key_nonce;
    vccrypt_buffer_t client_challenge_nonce;
    vccrypt_buffer_t shared_secret;
    vccrypt_buffer_t out;
    vccrypt_buffer_t read_server_pubkey;
    vccrypt_buffer_t read_server_challenge_nonce;
    vccrypt_buffer_t read_shared_secret;
    uint32_t offset, status;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the crypto suite. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create prng instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_prng_init(&suite, &prng));

    /* create cipher key agreement instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_cipher_key_agreement_init(
            &suite, &cipher_key_agreement));

    /* create client private key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
            &suite, &client_privkey));

    /* create client public key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &suite, &client_pubkey));

    /* create client keypair. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_key_agreement_keypair_create(
            &cipher_key_agreement, &client_privkey, &client_pubkey));

    /* create server private key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
            &suite, &server_privkey));

    /* create server public key buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
            &suite, &server_pubkey));

    /* create server keypair. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_key_agreement_keypair_create(
            &cipher_key_agreement, &server_privkey, &server_pubkey));

    /* create client key nonce buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &client_key_nonce));

    /* create client key nonce. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_prng_read(&prng, &client_key_nonce, client_key_nonce.size));

    /* create client challenge nonce buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_auth_key_agreement_nonce(
            &suite, &client_challenge_nonce));

    /* create client challenge nonce. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_prng_read(
            &prng, &client_challenge_nonce, client_challenge_nonce.size));

    /* create server key nonce buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &server_key_nonce));

    /* create server key nonce. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_prng_read(
            &prng, &server_key_nonce, server_key_nonce.size));

    /* create server challenge nonce buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_auth_key_agreement_nonce(
            &suite, &server_challenge_nonce));

    /* create server challenge nonce. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_prng_read(
            &prng, &server_challenge_nonce, server_challenge_nonce.size));

    /* create server cr mac buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_mac_authentication_code(
            &suite, &server_cr_hmac, true));

    /* clear it for now. */
    memset(server_cr_hmac.data, 0, server_cr_hmac.size);

    /* build response packet. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_resp_handshake_request(
            &out, &suite, EXPECTED_OFFSET, EXPECTED_STATUS, &EXPECTED_AGENT_ID,
            &server_pubkey, &server_key_nonce, &server_challenge_nonce,
            &server_cr_hmac));

    /* create shared secret buffer. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &suite, &shared_secret));

    /* derive shared secret. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vccrypt_key_agreement_short_term_secret_create(
            &cipher_key_agreement, &client_privkey, &server_pubkey,
            &server_key_nonce, &client_key_nonce, &shared_secret));

    /* create mac instance. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vccrypt_suite_mac_short_init(&suite, &mac, &shared_secret));

    /* mac initial packet bytes. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vccrypt_mac_digest(
            &mac, (const uint8_t*)out.data, out.size - server_cr_hmac.size));

    /* mac client challenge nonce. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vccrypt_mac_digest(
            &mac, (const uint8_t*)client_challenge_nonce.data,
            client_challenge_nonce.size));

    /* finalize. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vccrypt_mac_finalize(&mac, &server_cr_hmac));

    /* copy bytes to response packet. */
    memcpy(
        ((uint8_t*)out.data) + out.size - server_cr_hmac.size,
        server_cr_hmac.data, server_cr_hmac.size);

    /* build dummy socket. */
    int state = 0;
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_ssock_init(
            &sock,
            [&](ssock*, void* buffer, size_t* size) -> int {
                uint32_t type = ntohl(SSOCK_DATA_TYPE_DATA_PACKET);
                switch (state)
                {
                    /* read the type. */
                    case 0:
                        if (*size != sizeof(uint32_t))
                            return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                        memcpy(buffer, &type, sizeof(type));
                        ++state;
                        return VCBLOCKCHAIN_STATUS_SUCCESS;

                    case 1:
                        if (*size != sizeof(uint32_t))
                            return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                        *((uint32_t*)buffer) = htonl(out.size);
                        ++state;
                        return VCBLOCKCHAIN_STATUS_SUCCESS;

                    case 2:
                        if (*size != out.size)
                            return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                        memcpy(buffer, out.data, out.size);
                        ++state;
                        return VCBLOCKCHAIN_STATUS_SUCCESS;

                    default:
                        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                }
            },
            [&](ssock*, const void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
            }));

    /* read the response. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_recvresp_handshake_request(
            &sock, &suite, &agent_id, &read_server_pubkey,
            &client_privkey, &client_key_nonce, &client_challenge_nonce,
            &read_server_challenge_nonce, &read_shared_secret, &offset,
            &status));

    /* verify the offset. */
    EXPECT_EQ(EXPECTED_OFFSET, offset);

    /* verify the status. */
    EXPECT_EQ(EXPECTED_STATUS, status);

    /* verify the read agent id. */
    ASSERT_EQ(
        0,
        memcmp(&EXPECTED_AGENT_ID, &agent_id, sizeof(EXPECTED_AGENT_ID)));

    /* verify the read server public key. */
    ASSERT_NE(nullptr, read_server_pubkey.data);
    ASSERT_EQ(server_pubkey.size, read_server_pubkey.size);
    EXPECT_EQ(
        0,
        memcmp(
            server_pubkey.data, read_server_pubkey.data, server_pubkey.size));

    /* verify the read server challenge nonce. */
    ASSERT_NE(nullptr, read_server_challenge_nonce.data);
    ASSERT_EQ(server_challenge_nonce.size, read_server_challenge_nonce.size);
    EXPECT_EQ(
        0,
        memcmp(
            server_challenge_nonce.data, read_server_challenge_nonce.data,
            server_challenge_nonce.size));

    /* verify the read shared secret. */
    ASSERT_NE(nullptr, read_shared_secret.data);
    ASSERT_EQ(shared_secret.size, read_shared_secret.size);
    EXPECT_EQ(
        0,
        memcmp(
            shared_secret.data, read_shared_secret.data, shared_secret.size));

    /* clean up. */
    dispose((disposable_t*)&sock);
    dispose((disposable_t*)&prng);
    dispose((disposable_t*)&cipher_key_agreement);
    dispose((disposable_t*)&mac);
    dispose((disposable_t*)&server_pubkey);
    dispose((disposable_t*)&server_privkey);
    dispose((disposable_t*)&server_key_nonce);
    dispose((disposable_t*)&server_challenge_nonce);
    dispose((disposable_t*)&server_cr_hmac);
    dispose((disposable_t*)&client_pubkey);
    dispose((disposable_t*)&client_privkey);
    dispose((disposable_t*)&client_key_nonce);
    dispose((disposable_t*)&client_challenge_nonce);
    dispose((disposable_t*)&shared_secret);
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&read_server_pubkey);
    dispose((disposable_t*)&read_server_challenge_nonce);
    dispose((disposable_t*)&read_shared_secret);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
