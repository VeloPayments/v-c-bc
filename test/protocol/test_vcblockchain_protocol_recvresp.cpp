/**
 * \file test/protocol/test_vcblockchain_protocol_recvresp.cpp
 *
 * Unit tests for receiving a response from the protocol.
 *
 * \copyright 2020-2022 Velo Payments, Inc.  All rights reserved.
 */

#include <queue>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol.h>
#include <vcblockchain/psock.h>
#include <vpr/allocator/malloc_allocator.h>

#include "../dummy_psock.h"

/* DISABLED GTEST */
#if 0

using namespace std;

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_psock;
RCPR_IMPORT_resource;

/**
 * Verify that vcblockchain_protocol_recvresp does runtime parameter checking on
 * its pointer parameters.
 */
TEST(test_vcblockchain_protocol_recvresp, parameter_checks)
{
    psock* sock;
    rcpr_allocator* alloc;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vccrypt_buffer_t shared_secret;
    vccrypt_buffer_t response;
    uint64_t server_iv = 0U;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create an RCPR allocator instance. */
    ASSERT_EQ(STATUS_SUCCESS, rcpr_malloc_allocator_create(&alloc));

    /* create the crypto suite. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create a buffer for holding the shared secret. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &suite, &shared_secret));

    /* create the dummy socket. */
    ASSERT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_psock_create(
            &sock, alloc,
            [&](psock*, void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_READ;
            },
            [&](psock*, const void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
            }));

    /* Verify that we get a VCBLOCKCHAIN_ERROR_INVALID_ARG if any of the pointer
     * parameters are NULL.
     */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_recvresp(
            nullptr, alloc, &suite, &server_iv, &shared_secret, &response));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_recvresp(
            sock, nullptr, &suite, &server_iv, &shared_secret, &response));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_recvresp(
            sock, alloc, nullptr, &server_iv, &shared_secret, &response));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_recvresp(
            sock, alloc, &suite, nullptr, &shared_secret, &response));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_recvresp(
            sock, alloc, &suite, &server_iv, nullptr, &response));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_recvresp(
            sock, alloc, &suite, &server_iv, &shared_secret, nullptr));

    /* cleanup. */
    ASSERT_EQ(STATUS_SUCCESS, resource_release(psock_resource_handle(sock)));
    ASSERT_EQ(
        STATUS_SUCCESS,
        resource_release(rcpr_allocator_resource_handle(alloc)));
    dispose((disposable_t*)&shared_secret);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * Happy path: if we write a request, we can get a decoded response.
 */
TEST(test_vcblockchain_protocol_recvresp, happy_path)
{
    const uint8_t SHARED_SECRET[32] = {
        0x2c, 0x4c, 0x67, 0xd9, 0xd7, 0xd6, 0x4f, 0x5e,
        0xb0, 0xf1, 0x30, 0xf5, 0xf3, 0x44, 0xbc, 0x69,
        0xdc, 0x4b, 0xff, 0xa0, 0x2e, 0xd8, 0x4c, 0xff,
        0x8a, 0x07, 0x42, 0xfa, 0x9b, 0x0e, 0xa2, 0xd7 };
    const uint8_t RESPONSE[12] = {
        0x00, 0x00, 0x00, 0x01, /* request id. */
        0x00, 0x00, 0x00, 0x32, /* offset. */
        0x00, 0x00, 0x00, 0x17  /* status. */ };

    psock* sock;
    rcpr_allocator* alloc;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vccrypt_buffer_t shared_secret;
    vccrypt_buffer_t response;
    uint64_t server_iv = 0U;
    const uint64_t EXPECTED_POST_IV = server_iv + 1;
    queue<uint8_t> stream_bytes;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create an RCPR allocator instance. */
    ASSERT_EQ(STATUS_SUCCESS, rcpr_malloc_allocator_create(&alloc));

    /* create the crypto suite. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create a buffer for holding the shared secret. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &suite, &shared_secret));
    ASSERT_EQ(sizeof(SHARED_SECRET), shared_secret.size);
    /* copy the shared secret to this buffer. */
    memcpy(shared_secret.data, SHARED_SECRET, shared_secret.size);

    /* create the dummy socket for writing the response. */
    ASSERT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_psock_create(
            &sock, alloc,
            [&](psock*, void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_READ;
            },
            [&](psock*, const void* vbuf, size_t* s) -> int {
                const uint8_t* buf = (const uint8_t*)vbuf;

                for (size_t i = 0; i < *s; ++i)
                {
                    stream_bytes.push(buf[i]);
                }

                return VCBLOCKCHAIN_STATUS_SUCCESS;
            }));

    /* write the response to the dummy socket. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        psock_write_authed_data(
            sock, server_iv, RESPONSE, sizeof(RESPONSE), &suite,
            &shared_secret));

    /* reset the dummy socket. */
    ASSERT_EQ(STATUS_SUCCESS, resource_release(psock_resource_handle(sock)));
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_psock_create(
            &sock, alloc,
            [&](psock*, void* vbuf, size_t* s) -> int {
                uint8_t* buf = (uint8_t*)vbuf;

                if (stream_bytes.size() < *s)
                    return VCBLOCKCHAIN_ERROR_SSOCK_READ;

                for (size_t i = 0; i < *s; ++i)
                {
                    buf[i] = stream_bytes.front();
                    stream_bytes.pop();
                }

                return VCBLOCKCHAIN_STATUS_SUCCESS;
            },
            [&](psock*, const void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
            }));

    /* precondition: response is null / 0. */
    response.data = nullptr;
    response.size = 0U;

    /* reading the response should succeed. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_recvresp(
            sock, alloc, &suite, &server_iv, &shared_secret, &response));

    /* the response should be populated with RESPONSE above. */
    ASSERT_NE(nullptr, response.data);
    ASSERT_EQ(sizeof(RESPONSE), response.size);
    EXPECT_EQ(0, memcmp(response.data, RESPONSE, response.size));

    /* the server IV should be incremented. */
    EXPECT_EQ(EXPECTED_POST_IV, server_iv);

    /* cleanup. */
    ASSERT_EQ(STATUS_SUCCESS, resource_release(psock_resource_handle(sock)));
    ASSERT_EQ(
        STATUS_SUCCESS,
        resource_release(rcpr_allocator_resource_handle(alloc)));
    dispose((disposable_t*)&shared_secret);
    dispose((disposable_t*)&response);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
#endif
