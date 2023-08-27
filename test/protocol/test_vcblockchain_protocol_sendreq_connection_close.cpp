/**
 * \file test/protocol/test_vcblockchain_protocol_sendreq_connection_close.cpp
 *
 * Unit tests for writing the connection close request to a server socket.
 *
 * \copyright 2021-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cstring>
#include <memory>
#include <minunit/minunit.h>
#include <queue>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

#include "../dummy_psock.h"

using namespace std;

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_psock;
RCPR_IMPORT_resource;

TEST_SUITE(test_vcblockchain_protocol_connection_close);

/**
 * Test the happy path.
 */
TEST(happy_path)
{
    psock* sock;
    rcpr_allocator* alloc;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    const uint64_t STARTING_SERVER_IV = 1;
    const uint64_t EXPECTED_SERVER_IV = 2;
    const uint64_t STARTING_CLIENT_IV = 1;
    const uint64_t EXPECTED_CLIENT_IV = 2;
    const uint32_t EXPECTED_OFFSET = 19;
    const uint8_t SHARED_SECRET[32] = {
        0x16, 0xac, 0x42, 0x3e, 0x91, 0x9d, 0x40, 0x6b,
        0xa6, 0x1c, 0x9a, 0x92, 0x70, 0x62, 0x2d, 0xe6,
        0x44, 0x55, 0xbd, 0xa3, 0xb3, 0x22, 0x48, 0xb0,
        0x8f, 0xd7, 0x58, 0xaf, 0x15, 0x71, 0x99, 0xf1 };
    vccrypt_buffer_t shared_secret;
    vccrypt_buffer_t out;
    uint64_t client_iv, server_iv;
    queue<uint8_t> stream;
    protocol_req_connection_close req;

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

    /* create the shared secret buffer. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
                    &suite, &shared_secret));
    TEST_ASSERT(sizeof(SHARED_SECRET) == shared_secret.size);
    memcpy(shared_secret.data, SHARED_SECRET, shared_secret.size);

    /* create the dummy socket. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == dummy_psock_create(
                    &sock, alloc,
                    [&](psock*, void*, size_t*) -> int {
                        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                    },
                    [&](psock*, const void* val, size_t* size) -> int {
                        const uint8_t* bval = (const uint8_t*)val;

                        for (size_t i = 0; i < *size; ++i)
                            stream.push(bval[i]);

                        return VCBLOCKCHAIN_STATUS_SUCCESS;
                    }));

    /* PRECONDITIONS - set the IVs to the starting IVs. */
    client_iv = STARTING_CLIENT_IV;
    server_iv = STARTING_SERVER_IV;

    /* writing the request should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vcblockchain_protocol_sendreq_connection_close(
                    sock, &suite, &client_iv, &shared_secret, EXPECTED_OFFSET));

    /* the iv should be updated. */
    TEST_EXPECT(EXPECTED_CLIENT_IV == client_iv);

    /* release the old socket. */
    TEST_ASSERT(
        STATUS_SUCCESS == resource_release(psock_resource_handle(sock)));

    /* initialize the socket for reading. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == dummy_psock_create(
                    &sock, alloc,
                    [&](psock*, void* val, size_t* size) -> int {
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
                    [&](psock*, const void*, size_t*) -> int {
                        return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
                    }));

    /* reading a response should succeed. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_recvresp(
                    sock, alloc, &suite, &server_iv, &shared_secret, &out));

    /* the iv should be updated. */
    TEST_EXPECT(EXPECTED_SERVER_IV == server_iv);

    /* we should be able to decode this request. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_decode_req_connection_close(
                    &req, out.data, out.size));

    /* the data should have been properly serialized. */
    TEST_EXPECT(PROTOCOL_REQ_ID_CLOSE == req.request_id);
    TEST_EXPECT(EXPECTED_OFFSET == req.offset);

    /* clean up. */
    TEST_ASSERT(
        STATUS_SUCCESS == resource_release(psock_resource_handle(sock)));
    TEST_ASSERT(
        STATUS_SUCCESS
            == resource_release(rcpr_allocator_resource_handle(alloc)));
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&shared_secret);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
