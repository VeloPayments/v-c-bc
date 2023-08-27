/**
 * \file psock/test_psock.cpp
 *
 * Test vcblockchain psock methods.
 *
 * \copyright 2022-2023 Velo-Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cstring>
#include <minunit/minunit.h>
#include <rcpr/socket_utilities.h>
#include <unistd.h>
#include <vcblockchain/psock.h>
#include <vpr/allocator.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_psock;
RCPR_IMPORT_resource;
RCPR_IMPORT_socket_utilities;

TEST_SUITE(psock_test);

/**
 * \brief We can read an authed packet from a psock instance.
 */
TEST(psock_read_authed_data_happy_path)
{
    int lhs, rhs;
    const char TEST_STRING[] = "This is a test.";
    void* str = nullptr;
    uint32_t str_size = 0;
    constexpr size_t ENC_PAYLOAD_SIZE =
        sizeof(uint32_t) + /* type */
        sizeof(uint32_t) + /* size */
        32 + /* hmac */
        15; /* string length */
    char TEST_PAYLOAD[ENC_PAYLOAD_SIZE] = { 0 };
    uint64_t iv = 12345;
    rcpr_allocator* rcpr_alloc;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;

    /* register the Velo V1 crypto suite. */
    vccrypt_suite_register_velo_v1();

    /* initialize the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the rcpr allocator. */
    TEST_ASSERT(STATUS_SUCCESS == rcpr_malloc_allocator_create(&rcpr_alloc));

    /* initialize the crypto suite. */
    TEST_ASSERT(
        STATUS_SUCCESS
            == vccrypt_suite_options_init(
                    &suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create a socket pair for testing. */
    TEST_ASSERT(
        STATUS_SUCCESS
            == socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* create a psock instance for the rhs. */
    psock* sock;
    TEST_ASSERT(
        STATUS_SUCCESS == psock_create_from_descriptor(&sock, rcpr_alloc, rhs));

    /* create a key for the stream cipher. */
    /* TODO - there should be a suite method for this. */
    vccrypt_buffer_t key;
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* set a null key. */
    memset(key.data, 0, key.size);

    /* create a stream cipher instance. */
    vccrypt_stream_context_t stream;
    TEST_ASSERT(0 == vccrypt_suite_stream_init(&suite, &stream, &key));

    /* create a MAC instance. */
    vccrypt_mac_context_t mac;
    TEST_ASSERT(0 == vccrypt_suite_mac_short_init(&suite, &mac, &key));

    /* create a MAC digest buffer. */
    /* TODO - there should be a suite method for this. */
    vccrypt_buffer_t digest;
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &digest, &alloc_opts, suite.mac_short_opts.mac_size));

    /* continue encryption from the current iv, offset 0. */
    TEST_ASSERT(
        0 == vccrypt_stream_continue_encryption(&stream, &iv, sizeof(iv), 0));

    /* write the packet type to the buffer. */
    uint32_t type = htonl(VCBLOCKCHAIN_PSOCK_BOXED_TYPE_AUTHED_PACKET);
    size_t offset = 0;
    TEST_ASSERT(
        0
            == vccrypt_stream_encrypt(
                    &stream, &type, sizeof(type), TEST_PAYLOAD, &offset));
    /* digest the packet type. */
    TEST_ASSERT(
        0
            == vccrypt_mac_digest(
                    &mac, (const uint8_t*)TEST_PAYLOAD + offset - sizeof(type),
                    sizeof(type)));

    /* write the payload size to the buffer. */
    uint32_t payload_size = htonl(15);
    TEST_ASSERT(
        0
            == vccrypt_stream_encrypt(
                    &stream, &payload_size, sizeof(payload_size), TEST_PAYLOAD,
                    &offset));
    /* digest the payload size. */
    TEST_ASSERT(
        0
            == vccrypt_mac_digest(
                    &mac,
                    (const uint8_t*)TEST_PAYLOAD + offset
                        - sizeof(payload_size),
                    sizeof(payload_size)));

    /* write the payload to the buffer, skipping the hmac. */
    TEST_ASSERT(
        0
            == vccrypt_stream_encrypt(
                    &stream, TEST_STRING, 15, TEST_PAYLOAD + 32, &offset));
    /* digest the payload. */
    TEST_ASSERT(
        0
            == vccrypt_mac_digest(
                    &mac, (const uint8_t*)TEST_PAYLOAD + 32 + offset - 15, 15));

    /* finalize the mac to the test payload. */
    TEST_ASSERT(0 == vccrypt_mac_finalize(&mac, &digest));
    memcpy(
        TEST_PAYLOAD + sizeof(type) + sizeof(payload_size), digest.data,
        digest.size);

    /* write the payload to the lhs socket. */
    TEST_ASSERT(
        (ssize_t)sizeof(TEST_PAYLOAD)
            == write(lhs, TEST_PAYLOAD, sizeof(TEST_PAYLOAD)));

    /* read an authed packet from the rhs socket. */
    TEST_ASSERT(
        0
            == psock_read_authed_data(
                    sock, rcpr_alloc, iv, &str, &str_size, &suite, &key));

    /* the data is valid. */
    TEST_ASSERT(nullptr != str);

    /* the string size is the length of our string. */
    TEST_ASSERT(strlen(TEST_STRING) == str_size);

    /* the data is a copy of the test string. */
    TEST_EXPECT(0 == memcmp(TEST_STRING, str, str_size));

    /* clean up. */
    TEST_ASSERT(STATUS_SUCCESS == rcpr_allocator_reclaim(rcpr_alloc, str));
    dispose((disposable_t*)&mac);
    dispose((disposable_t*)&digest);
    dispose((disposable_t*)&stream);
    dispose((disposable_t*)&key);
    TEST_ASSERT(
        STATUS_SUCCESS == resource_release(psock_resource_handle(sock)));
    TEST_ASSERT(0 == close(lhs));
    dispose((disposable_t*)&suite);
    TEST_ASSERT(
        STATUS_SUCCESS
            == resource_release(rcpr_allocator_resource_handle(rcpr_alloc)));
    dispose((disposable_t*)&alloc_opts);
}

/**
 * \brief We can read an authed packed from a socket that was written by
 * psock_write_authed_data.
 */
TEST(psock_write_authed_data_happy_path)
{
    int lhs, rhs;
    const char TEST_STRING[] = "This is a test.";
    void* str = nullptr;
    uint32_t str_size = 0;
    uint64_t iv = 12345;
    rcpr_allocator* rcpr_alloc;
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;

    /* register the Velo V1 crypto suite. */
    vccrypt_suite_register_velo_v1();

    /* initialize the malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the rcpr allocator. */
    TEST_ASSERT(STATUS_SUCCESS == rcpr_malloc_allocator_create(&rcpr_alloc));

    /* initialize the crypto suite. */
    TEST_ASSERT(
        STATUS_SUCCESS
            == vccrypt_suite_options_init(
                    &suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create a socket pair for testing. */
    TEST_ASSERT(
        STATUS_SUCCESS
            == socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* create a psock instance for the rhs. */
    psock* lsock;
    TEST_ASSERT(
        STATUS_SUCCESS
            == psock_create_from_descriptor(&lsock, rcpr_alloc, lhs));

    /* create a psock instance for the rhs. */
    psock* rsock;
    TEST_ASSERT(
        STATUS_SUCCESS
            == psock_create_from_descriptor(&rsock, rcpr_alloc, rhs));

    /* create key for stream cipher. */
    /* TODO - there should be a suite method for this. */
    vccrypt_buffer_t key;
    TEST_ASSERT(
        0
            == vccrypt_buffer_init(
                    &key, &alloc_opts, suite.stream_cipher_opts.key_size));

    /* set a null key. */
    memset(key.data, 0, key.size);

    /* writing to the socket should succeed. */
    TEST_ASSERT(
        0
            == psock_write_authed_data(
                    lsock, iv, TEST_STRING, strlen(TEST_STRING), &suite, &key));

    /* read an authed packet from the rhs socket. */
    TEST_ASSERT(
        0
            == psock_read_authed_data(
                    rsock, rcpr_alloc, iv, &str, &str_size, &suite, &key));

    /* the data is valid. */
    TEST_ASSERT(nullptr != str);

    /* the string size is the length of our string. */
    TEST_ASSERT(strlen(TEST_STRING) == str_size);

    /* the data is a copy of the test string. */
    TEST_EXPECT(0 == memcmp(TEST_STRING, str, str_size));

    /* clean up. */
    TEST_ASSERT(STATUS_SUCCESS == rcpr_allocator_reclaim(rcpr_alloc, str));
    TEST_ASSERT(
        STATUS_SUCCESS == resource_release(psock_resource_handle(lsock)));
    TEST_ASSERT(
        STATUS_SUCCESS == resource_release(psock_resource_handle(rsock)));
    dispose((disposable_t*)&key);
    dispose((disposable_t*)&suite);
    TEST_ASSERT(
        STATUS_SUCCESS
            == resource_release(rcpr_allocator_resource_handle(rcpr_alloc)));
    dispose((disposable_t*)&alloc_opts);
}
