/**
 * \file
 * test/protocol/test_vcblockchain_protocol_sendreq_extended_api_response.cpp
 *
 * Unit tests for writing an extended API response request to a server socket.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <memory>
#include <queue>
#include <vcblockchain/protocol.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

#include "../ssock/dummy_ssock.h"

using namespace std;

/**
 * Test the happy path.
 */
TEST(test_vcblockchain_protocol_sendreq_extended_api_response, happy_path)
{
    ssock sock;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    const uint64_t STARTING_SERVER_IV = 1;
    const uint64_t EXPECTED_SERVER_IV = 2;
    const uint64_t STARTING_CLIENT_IV = 1;
    const uint64_t EXPECTED_CLIENT_IV = 2;
    const uint64_t EXPECTED_OFFSET = 19;
    const uint32_t EXPECTED_STATUS = 91;
    const uint8_t SHARED_SECRET[32] = {
        0x16, 0xac, 0x42, 0x3e, 0x91, 0x9d, 0x40, 0x6b,
        0xa6, 0x1c, 0x9a, 0x92, 0x70, 0x62, 0x2d, 0xe6,
        0x44, 0x55, 0xbd, 0xa3, 0xb3, 0x22, 0x48, 0xb0,
        0x8f, 0xd7, 0x58, 0xaf, 0x15, 0x71, 0x99, 0xf1 };
    vccrypt_buffer_t shared_secret;
    vccrypt_buffer_t out;
    uint64_t client_iv, server_iv;
    queue<uint8_t> stream;
    protocol_req_extended_api_response req;
    vccrypt_buffer_t response_body;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a dummy response body. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&response_body, &alloc_opts, 32));
    memset(response_body.data, 0xef, response_body.size);

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

    /* PRECONDITIONS - set the IVs to the starting IVs. */
    client_iv = STARTING_CLIENT_IV;
    server_iv = STARTING_SERVER_IV;

    /* writing the request should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vcblockchain_protocol_sendreq_extended_api_response(
            &sock, &suite, &client_iv, &shared_secret, EXPECTED_OFFSET,
            EXPECTED_STATUS, &response_body));

    /* the iv should be updated. */
    EXPECT_EQ(EXPECTED_CLIENT_IV, client_iv);

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

    /* the iv should be updated. */
    EXPECT_EQ(EXPECTED_SERVER_IV, server_iv);

    /* we should be able to decode this request. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_decode_req_extended_api_response(
            &req, &alloc_opts, out.data, out.size));

    /* the data should have been properly serialized. */
    EXPECT_EQ(PROTOCOL_REQ_ID_EXTENDED_API_SENDRESP, req.request_id);
    EXPECT_EQ(EXPECTED_OFFSET, req.offset);
    EXPECT_EQ(EXPECTED_STATUS, req.status);
    ASSERT_NE(nullptr, req.response_body.data);
    ASSERT_EQ(response_body.size, req.response_body.size);
    EXPECT_EQ(
        0,
        memcmp(req.response_body.data, response_body.data, response_body.size));

    /* clean up. */
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&response_body);
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&sock);
    dispose((disposable_t*)&shared_secret);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
