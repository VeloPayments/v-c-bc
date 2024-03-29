/**
 * \file test/protocol/test_vcblockchain_protocol_recvresp_handshake_request.cpp
 *
 * Unit tests for receiving the handshake request from a server socket.
 *
 * \copyright 2020-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

#include "../dummy_psock.h"

using namespace std;

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_psock;
RCPR_IMPORT_resource;

TEST_SUITE(test_vcblockchain_protocol_recvresp_handshake_request);

/**
 * Test the happy path.
 */
TEST(happy_path)
{
    psock* sock;
    rcpr_allocator* alloc;
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

    /* create an RCPR allocator instance. */
    TEST_ASSERT(STATUS_SUCCESS == rcpr_malloc_allocator_create(&alloc));

    /* create the crypto suite. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_options_init(
                    &suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create prng instance. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_prng_init(&suite, &prng));

    /* create cipher key agreement instance. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_cipher_key_agreement_init(
                    &suite, &cipher_key_agreement));

    /* create client private key buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
                    &suite, &client_privkey));

    /* create client public key buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
                    &suite, &client_pubkey));

    /* create client keypair. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_key_agreement_keypair_create(
                    &cipher_key_agreement, &client_privkey, &client_pubkey));

    /* create server private key buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_private_key(
                    &suite, &server_privkey));

    /* create server public key buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_public_key(
                    &suite, &server_pubkey));

    /* create server keypair. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_key_agreement_keypair_create(
                    &cipher_key_agreement, &server_privkey, &server_pubkey));

    /* create client key nonce buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
                    &suite, &client_key_nonce));

    /* create client key nonce. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_prng_read(
                    &prng, &client_key_nonce, client_key_nonce.size));

    /* create client challenge nonce buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
                    &suite, &client_challenge_nonce));

    /* create client challenge nonce. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_prng_read(
                    &prng, &client_challenge_nonce,
                    client_challenge_nonce.size));

    /* create server key nonce buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
                    &suite, &server_key_nonce));

    /* create server key nonce. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_prng_read(
                    &prng, &server_key_nonce, server_key_nonce.size));

    /* create server challenge nonce buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
                    &suite, &server_challenge_nonce));

    /* create server challenge nonce. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_prng_read(
                    &prng, &server_challenge_nonce,
                    server_challenge_nonce.size));

    /* create server cr mac buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_mac_authentication_code(
                    &suite, &server_cr_hmac, true));

    /* clear it for now. */
    memset(server_cr_hmac.data, 0, server_cr_hmac.size);

    /* build response packet. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_handshake_request(
                    &out, &suite, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &EXPECTED_AGENT_ID, &server_pubkey, &server_key_nonce,
                    &server_challenge_nonce, &server_cr_hmac));

    /* create shared secret buffer. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
                    &suite, &shared_secret));

    /* derive shared secret. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vccrypt_key_agreement_short_term_secret_create(
                    &cipher_key_agreement, &client_privkey, &server_pubkey,
                    &server_key_nonce, &client_key_nonce, &shared_secret));

    /* create mac instance. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vccrypt_suite_mac_short_init(&suite, &mac, &shared_secret));

    /* mac initial packet bytes. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vccrypt_mac_digest(
                    &mac, (const uint8_t*)out.data,
                    out.size - server_cr_hmac.size));

    /* mac client challenge nonce. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vccrypt_mac_digest(
                    &mac, (const uint8_t*)client_challenge_nonce.data,
                    client_challenge_nonce.size));

    /* finalize. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vccrypt_mac_finalize(&mac, &server_cr_hmac));

    /* copy bytes to response packet. */
    memcpy(
        ((uint8_t*)out.data) + out.size - server_cr_hmac.size,
        server_cr_hmac.data, server_cr_hmac.size);

    /* build dummy socket. */
    int state = 0;
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == dummy_psock_create(
                    &sock, alloc,
                    [&](psock*, void* buffer, size_t* size) -> int {
                        uint32_t type = ntohl(PSOCK_BOXED_TYPE_DATA);
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
                    [&](psock*, const void*, size_t*) -> int {
                        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
                    }));

    /* read the response. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_recvresp_handshake_request(
                    sock, alloc, &suite, &agent_id, &read_server_pubkey,
                    &client_privkey, &client_key_nonce, &client_challenge_nonce,
                    &read_server_challenge_nonce, &read_shared_secret, &offset,
                    &status));

    /* verify the offset. */
    TEST_EXPECT(EXPECTED_OFFSET == offset);

    /* verify the status. */
    TEST_EXPECT(EXPECTED_STATUS == status);

    /* verify the read agent id. */
    TEST_ASSERT(
        0
            == memcmp(
                    &EXPECTED_AGENT_ID, &agent_id, sizeof(EXPECTED_AGENT_ID)));

    /* verify the read server public key. */
    TEST_ASSERT(nullptr != read_server_pubkey.data);
    TEST_ASSERT(server_pubkey.size == read_server_pubkey.size);
    TEST_EXPECT(
        0
            == memcmp(
                    server_pubkey.data, read_server_pubkey.data,
                    server_pubkey.size));

    /* verify the read server challenge nonce. */
    TEST_ASSERT(nullptr != read_server_challenge_nonce.data);
    TEST_ASSERT(
        server_challenge_nonce.size == read_server_challenge_nonce.size);
    TEST_EXPECT(
        0
            == memcmp(
                    server_challenge_nonce.data,
                    read_server_challenge_nonce.data,
                    server_challenge_nonce.size));

    /* verify the read shared secret. */
    TEST_ASSERT(nullptr != read_shared_secret.data);
    TEST_ASSERT(shared_secret.size == read_shared_secret.size);
    TEST_EXPECT(
        0
            == memcmp(
                    shared_secret.data, read_shared_secret.data,
                    shared_secret.size));

    /* clean up. */
    TEST_ASSERT(
        STATUS_SUCCESS == resource_release(psock_resource_handle(sock)));
    TEST_ASSERT(
        STATUS_SUCCESS
            == resource_release(rcpr_allocator_resource_handle(alloc)));
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
