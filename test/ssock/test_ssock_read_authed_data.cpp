/**
 * \file test/ssock/test_ssock_read_authed_data.cpp
 *
 * Unit tests for ssock_read_authed_data.
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <vpr/allocator/malloc_allocator.h>

#include "dummy_ssock.h"

using namespace std;

/**
 * Test that ssock_read_authed_data does runtime parameter checks.
 */
TEST(test_ssock_read_authed_data, parameter_checks)
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

    void* val = nullptr;
    uint32_t size = 0U;
    uint64_t iv = 0U;

    /* call with an invalid socket. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_authed_data(
            nullptr, &alloc_opts, iv, &val, &size, &suite, &secret));

    /* call with an invalid allocator. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_authed_data(
            &sock, nullptr, iv, &val, &size, &suite, &secret));

    /* call with an invalid value. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_authed_data(
            &sock, &alloc_opts, iv, nullptr, &size, &suite, &secret));

    /* call with an invalid size pointer. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_authed_data(
            &sock, &alloc_opts, iv, &val, nullptr, &suite, &secret));

    /* call with an invalid crypto suite. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_authed_data(
            &sock, &alloc_opts, iv, &val, &size, nullptr, &secret));

    /* call with an invalid shared secret. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_authed_data(
            &sock, &alloc_opts, iv, &val, &size, &suite, nullptr));

    /* clean up. */
    dispose((disposable_t*)&sock);
    dispose((disposable_t*)&secret);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * Test that we can read authed data in the happy path.
 */
TEST(test_ssock_read_authed_data, happy_path)
{
    ssock sock;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vccrypt_buffer_t shared_secret;
    vccrypt_stream_context_t stream;
    vccrypt_mac_context_t mac;
    vccrypt_buffer_t header;
    vccrypt_buffer_t encrypted_header;
    vccrypt_buffer_t encrypted_payload;
    vccrypt_buffer_t digest;
    const uint8_t SHARED_SECRET[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, };
    const uint64_t IV = 0U;
    const uint8_t EXPECTED_PAYLOAD[8] = {
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 };
    uint8_t* val;
    uint32_t size = 0U;

    /* register the crypto suite. */
    vccrypt_suite_register_velo_v1();

    /* create malloc allocator. */
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

    /* copy our shared secret bytes. */
    ASSERT_EQ(sizeof(SHARED_SECRET), shared_secret.size);
    memcpy(shared_secret.data, SHARED_SECRET, shared_secret.size);

    /* create a mac instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_mac_short_init(&suite, &mac, &shared_secret));

    /* create a stream cipher instance. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_stream_init(&suite, &stream, &shared_secret));

    /* compute header size. */
    size_t header_size =
          sizeof(uint32_t)
        + sizeof(uint32_t);
    size_t encrypted_header_size =
          sizeof(uint32_t)
        + sizeof(uint32_t)
        + suite.mac_short_opts.mac_size;

    /* create header buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &header, &alloc_opts, header_size));
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &encrypted_header, &alloc_opts, encrypted_header_size));

    /* populate header buffer. */
    uint8_t* pheader = (uint8_t*)header.data;
    uint32_t net_payload_type = ntohl(SSOCK_DATA_TYPE_AUTHED_PACKET);
    memcpy(pheader, &net_payload_type, sizeof(net_payload_type));
    pheader += sizeof(net_payload_type);
    uint32_t payload_size = sizeof(EXPECTED_PAYLOAD);
    uint32_t net_payload_size = htonl(payload_size);
    memcpy(pheader, &net_payload_size, sizeof(net_payload_size));
    pheader += sizeof(net_payload_size);

    /* start encryption. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_stream_continue_encryption(
            &stream, &IV, sizeof(IV), 0));

    /* encrypt header buffer. */
    size_t offset = 0;
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_stream_encrypt(
            &stream, header.data, header_size, encrypted_header.data, &offset));

    /* continue encryption for the encrypted payload. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_stream_continue_encryption(
            &stream, &IV, sizeof(IV), offset));

    /* create payload buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(
            &encrypted_payload, &alloc_opts, sizeof(EXPECTED_PAYLOAD)));

    /* reset the offset. */
    offset = 0;

    /* encrypt payload. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_stream_encrypt(
            &stream, EXPECTED_PAYLOAD, sizeof(EXPECTED_PAYLOAD),
            encrypted_payload.data, &offset));

    /* mac encrypted header buffer and encrypted payload buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mac_digest(&mac, (uint8_t*)encrypted_header.data, header_size));
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_mac_digest(
            &mac, (uint8_t*)encrypted_payload.data, encrypted_payload.size));

    /* create buffer to hold mac. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_mac_authentication_code(
            &suite, &digest, true));

    /* finalize mac. */
    ASSERT_EQ(VCCRYPT_STATUS_SUCCESS, vccrypt_mac_finalize(&mac, &digest));

    /* copy mac to encrypted header buffer. */
    uint8_t* peheader = (uint8_t*)encrypted_header.data;
    peheader += header.size;
    memcpy(peheader, digest.data, digest.size);

    /* create dummy socket that returns hedaer then payload. */
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
                        if (*sz != encrypted_header.size)
                            return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                        memcpy(b, encrypted_header.data, *sz);
                        ++state;
                        return VCBLOCKCHAIN_STATUS_SUCCESS;

                    /* payload read. */
                    case 1:
                        if (*sz != encrypted_payload.size)
                            return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                        memcpy(b, encrypted_payload.data, *sz);
                        ++state;
                        return VCBLOCKCHAIN_STATUS_SUCCESS;

                    default:
                        return VCBLOCKCHAIN_ERROR_SSOCK_READ;
                }
            },
            [&](ssock*, const void*, size_t*) -> int {
                return VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
            }));

    /* read packet from dummy socket. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        ssock_read_authed_data(
            &sock, &alloc_opts, IV, (void**)&val, &size, &suite,
            &shared_secret));

    /* verify payload. */
    ASSERT_EQ(sizeof(EXPECTED_PAYLOAD), size);
    ASSERT_EQ(0, memcmp(val, EXPECTED_PAYLOAD, size));

    /* clean up. */
    release(&alloc_opts, val);
    dispose((disposable_t*)&sock);
    dispose((disposable_t*)&header);
    dispose((disposable_t*)&encrypted_header);
    dispose((disposable_t*)&encrypted_payload);
    dispose((disposable_t*)&digest);
    dispose((disposable_t*)&stream);
    dispose((disposable_t*)&mac);
    dispose((disposable_t*)&shared_secret);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
