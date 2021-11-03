/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_req_handshake_request.cpp
 *
 * Unit tests for encoding the request portion of the handshake request.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

/**
 * Test the basics of the encoding.
 */
TEST(test_vcblockchain_protocol_encode_req_handshake_request, basics)
{
    allocator_options_t alloc_opts;
    vccrypt_suite_options_t suite;
    vpr_uuid client_id = { .data = {
        0x6e, 0x48, 0xf1, 0x40, 0x6d, 0xbf, 0x4e, 0x8d,
        0xba, 0x0b, 0xf3, 0xcd, 0xba, 0x7b, 0x0c, 0xa8 } };
    vccrypt_buffer_t client_key_nonce;
    vccrypt_buffer_t client_challenge_nonce;
    vccrypt_buffer_t out;
    const uint32_t EXPECTED_OFFSET = 17;

    /* register the suite. */
    vccrypt_suite_register_velo_v1();

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create the crypto suite. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_options_init(&suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create a buffer for holding the key nonce. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &client_key_nonce));
    /* set the key nonce value. */
    memset(client_key_nonce.data, 0xFE, client_key_nonce.size);

    /* create a buffer for holding the challenge nonce. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
            &suite, &client_challenge_nonce));
    /* set the challenge nonce. */
    memset(client_challenge_nonce.data, 0xEC, client_challenge_nonce.size);

    /* PRECONDITION: output should have a null data and 0 size. */
    out.data = nullptr;
    out.size = 0U;

    /* encoding the handshake request should succeed. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_handshake_request(
            &out, &suite, EXPECTED_OFFSET, &client_id, &client_key_nonce,
            &client_challenge_nonce));

    /* the out data and size should be set. */
    ASSERT_NE(nullptr, out.data);
    ASSERT_NE(0U, out.size);

    /* get a byte pointer to the output buffer. */
    const uint8_t* buf = (const uint8_t*)out.data;
    size_t size = out.size;

    /* the first four bytes should be the request id. */
    uint32_t net_request;
    ASSERT_GE(size, sizeof(net_request));
    memcpy(&net_request, buf, sizeof(net_request));
    EXPECT_EQ(PROTOCOL_REQ_ID_HANDSHAKE_INITIATE, ntohl(net_request));
    buf += sizeof(net_request); size -= sizeof(net_request);

    /* then comes the offset. */
    uint32_t net_offset;
    ASSERT_GE(size, sizeof(net_offset));
    memcpy(&net_offset, buf, sizeof(net_offset));
    EXPECT_EQ(EXPECTED_OFFSET, ntohl(net_offset));
    buf += sizeof(net_offset); size -= sizeof(net_offset);

    /* then the protocol version. */
    uint32_t net_protocol_version;
    ASSERT_GE(size, sizeof(net_protocol_version));
    memcpy(&net_protocol_version, buf, sizeof(net_protocol_version));
    EXPECT_EQ(PROTOCOL_VERSION_0_1_DEMO, ntohl(net_protocol_version));
    buf += sizeof(net_protocol_version); size -= sizeof(net_protocol_version);

    /* the the crypto suite. */
    uint32_t net_crypto_suite;
    ASSERT_GE(size, sizeof(net_crypto_suite));
    memcpy(&net_crypto_suite, buf, sizeof(net_crypto_suite));
    EXPECT_EQ(VCCRYPT_SUITE_VELO_V1, ntohl(net_crypto_suite));
    buf += sizeof(net_crypto_suite); size -= sizeof(net_crypto_suite);

    /* then the client id. */
    ASSERT_GE(size, sizeof(client_id));
    EXPECT_EQ(0, memcmp(buf, &client_id, sizeof(client_id)));
    buf += sizeof(client_id); size -= sizeof(client_id);

    /* then the key nonce. */
    ASSERT_GE(size, client_key_nonce.size);
    EXPECT_EQ(0, memcmp(buf, client_key_nonce.data, client_key_nonce.size));
    buf += client_key_nonce.size; size -= client_key_nonce.size;

    /* finally, the challenge nonce. */
    ASSERT_EQ(client_challenge_nonce.size, size);
    EXPECT_EQ(
        0,
        memcmp(buf, client_challenge_nonce.data, client_challenge_nonce.size));

    /* clean up. */
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&client_key_nonce);
    dispose((disposable_t*)&client_challenge_nonce);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
