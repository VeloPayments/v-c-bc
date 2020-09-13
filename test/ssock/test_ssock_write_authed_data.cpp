/**
 * \file test/ssock/test_ssock_write_authed_data.cpp
 *
 * Unit tests for ssock_write_authed_data.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <vpr/allocator/malloc_allocator.h>

#include "dummy_ssock.h"

using namespace std;

/**
 * Test that ssock_write_authed_data does runtime parameter checks.
 */
TEST(test_ssock_write_authed_data, parameter_checks)
{
    ssock sock;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vccrypt_buffer_t secret;

    /* register the crypto suite. */
    vccrypt_suite_register_velo_v1();

    /* create malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the crypto suite. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create the buffer for the shared secret. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_shared_secret(
            &suite, &secret));

    /* build a simple dummy socket. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_ssock_init(
            &sock,
            [&](ssock*, void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_READ;
            },
            [&](ssock*, const void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
            }));

    uint8_t val[] = { 1, 2, 3 };
    uint32_t size = sizeof(val);
    uint64_t iv = 0U;

    /* call with an invalid socket. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_write_authed_data(
            nullptr, iv, val, size, &suite, &secret));

    /* call with an invalid value. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_write_authed_data(
            &sock, iv, nullptr, size, &suite, &secret));

    /* call with an invalid crypto suite. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_write_authed_data(
            &sock, iv, val, size, nullptr, &secret));

    /* call with an invalid shared secret. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_write_authed_data(
            &sock, iv, val, size, &suite, nullptr));

    /* clean up. */
    dispose((disposable_t*)&sock);
    dispose((disposable_t*)&secret);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * Test that we can write authed data in the happy path.
 */
TEST(test_ssock_write_authed_data, happy_path)
{
    ssock sock;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vccrypt_buffer_t shared_secret;
    const uint8_t SHARED_SECRET[32] = {
        0x69, 0x1a, 0xa9, 0x75, 0x4a, 0x45, 0x4e, 0xa6,
        0x96, 0xbe, 0x6b, 0xbe, 0x30, 0xf5, 0x7b, 0x59,
        0x3d, 0xce, 0xa4, 0x6b, 0xdb, 0x40, 0x4f, 0x35,
        0xab, 0x99, 0xe6, 0x32, 0x08, 0x6a, 0x73, 0x03 };
    const uint64_t IV = 19U;
    const uint8_t EXPECTED_PAYLOAD[4] = {
        0x07, 0x08, 0x09, 0x0a };
    uint8_t* captured_val;
    uint32_t captured_size = 0U;
    uint8_t* val;
    uint32_t size = 0U;

    /* register the crypto suite. */
    vccrypt_suite_register_velo_v1();

    /* create the malloc allocator. */
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

    /* copy our shared secret to the buffer. */
    ASSERT_EQ(sizeof(SHARED_SECRET), shared_secret.size);
    memcpy(shared_secret.data, SHARED_SECRET, shared_secret.size);

    /* create a dummy ssock instance for capturing the data. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_ssock_init(
            &sock,
            [&](ssock*, void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_READ;
            },
            [&](ssock*, const void* buf, size_t* sz) -> int {
                captured_size = *sz;
                captured_val = (uint8_t*)malloc(*sz);
                if (nullptr == captured_val)
                {
                    return VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
                }

                memcpy(captured_val, buf, captured_size);

                return VCBLOCKCHAIN_STATUS_SUCCESS;
            }));

    /* writing the authed packet should succeed. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        ssock_write_authed_data(
            &sock, IV, EXPECTED_PAYLOAD, sizeof(EXPECTED_PAYLOAD), &suite,
            &shared_secret));

    /* dispose of the dummy sock. */
    dispose((disposable_t*)&sock);

    /* create a dummy sock for the read. */
    int state = 0;
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_ssock_init(
            &sock,
            [&](ssock*, void* b, size_t* sz) -> int {
                switch (state)
                {
                    /* header read. */
                    case 0:
                        if (*sz != 37)
                            return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                        memcpy(b, captured_val, *sz);
                        ++state;
                        return VCBLOCKCHAIN_STATUS_SUCCESS;

                    /* payload read. */
                    case 1:
                        if (*sz != sizeof(EXPECTED_PAYLOAD))
                            return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                        memcpy(b, captured_val + 37, *sz);
                        ++state;
                        return VCBLOCKCHAIN_STATUS_SUCCESS;

                    /* invalid read. */
                    default:
                        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                }
            },
            [&](ssock*, const void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
            }));

    /* read the packet from the dummy socket. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        ssock_read_authed_data(
            &sock, &alloc_opts, IV, (void**)&val, &size, &suite,
            &shared_secret));

    /* verify the payload. */
    ASSERT_EQ(sizeof(EXPECTED_PAYLOAD), size);
    ASSERT_EQ(0, memcmp(val, EXPECTED_PAYLOAD, size));

    /* clean up. */
    release(&alloc_opts, val);
    free(captured_val);
    dispose((disposable_t*)&sock);
    dispose((disposable_t*)&shared_secret);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
