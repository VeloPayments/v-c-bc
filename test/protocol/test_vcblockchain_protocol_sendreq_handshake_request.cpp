/**
 * \file test/protocol/test_vcblockchain_protocol_sendreq_handshake_request.cpp
 *
 * Unit tests for writing the handshake request to a server socket.
 *
 * \copyright 2020-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <memory>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol.h>
#include <vpr/allocator/malloc_allocator.h>

#include "../dummy_psock.h"

using namespace std;

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_psock;
RCPR_IMPORT_resource;

TEST_SUITE(test_vcblockchain_protocol_sendreq_handshake_request);

/**
 * Test the happy path.
 */
TEST(happy_path)
{
    psock* sock;
    rcpr_allocator* alloc;
    vector<shared_ptr<psock_write_params>> write_calls;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vpr_uuid client_id = { .data = {
        0x6e, 0x48, 0xf1, 0x40, 0x6d, 0xbf, 0x4e, 0x8d,
        0xba, 0x0b, 0xf3, 0xcd, 0xba, 0x7b, 0x0c, 0xa8 } };
    vccrypt_buffer_t client_key_nonce;
    vccrypt_buffer_t client_challenge_nonce;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create an RCPR allocator instance. */
    TEST_ASSERT(
        STATUS_SUCCESS
            == rcpr_malloc_allocator_create(&alloc));

    /* create the crypto suite. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_options_init(
                    &suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create the dummy socket. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == dummy_psock_create(
                    &sock, alloc,
                    [&](psock*, void*, size_t*) -> int {
                        return VCBLOCKCHAIN_STATUS_SUCCESS;
                    },
                    [&](psock* sock, const void* val, size_t* size) -> int {
                        write_calls.push_back(
                            make_shared<psock_write_params>(
                                sock, val, *size));

                        return VCBLOCKCHAIN_STATUS_SUCCESS;
                    }));

    /* PRECONDITIONS - set the buffers to null. */
    client_key_nonce.data = nullptr;
    client_key_nonce.size = 0U;
    client_challenge_nonce.data = nullptr;
    client_challenge_nonce.size = 0U;

    /* writing the handshake request should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vcblockchain_protocol_sendreq_handshake_request(
                    sock, &suite, &client_id, &client_key_nonce,
                    &client_challenge_nonce));

    /* the buffer data and size values should be set. */
    TEST_ASSERT(nullptr != client_key_nonce.data);
    TEST_ASSERT(
        suite.key_cipher_opts.minimum_nonce_size == client_key_nonce.size);
    TEST_ASSERT(nullptr != client_challenge_nonce.data);
    TEST_ASSERT(
        suite.key_cipher_opts.minimum_nonce_size
            == client_challenge_nonce.size);

    /* sock write should have been called once. */
    TEST_ASSERT(3U == write_calls.size());

    /* first call is the type. */
    TEST_EXPECT(sock == write_calls[0]->sock);
    TEST_EXPECT(sizeof(uint32_t) == write_calls[0]->buf.size());

    /* second call is the size. */
    TEST_EXPECT(sock == write_calls[1]->sock);
    TEST_EXPECT(sizeof(uint32_t) == write_calls[1]->buf.size());

    /* the socket is the first argument. */
    TEST_EXPECT(sock == write_calls[2]->sock);

    /* compute the size of the request packet payload. */
    size_t expected_payload_size =
          sizeof(uint32_t) /* request_id */
        + sizeof(uint32_t) /* offset */
        + sizeof(uint32_t) /* protocol version */
        + sizeof(uint32_t) /* crypto suite */
        + sizeof(client_id) /* client id */
        + client_key_nonce.size /* key nonce size */
        + client_challenge_nonce.size; /* challenge nonce size */

    /* the buffer written was the correct size for the payload. */
    TEST_EXPECT(expected_payload_size == write_calls[2]->buf.size());

    /* clean up. */
    TEST_ASSERT(
        STATUS_SUCCESS == resource_release(psock_resource_handle(sock)));
    TEST_ASSERT(
        STATUS_SUCCESS
            == resource_release(rcpr_allocator_resource_handle(alloc)));
    dispose((disposable_t*)&client_key_nonce);
    dispose((disposable_t*)&client_challenge_nonce);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
