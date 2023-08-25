/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_req_handshake_request.cpp
 *
 * Unit tests for encoding the request portion of the handshake request.
 *
 * \copyright 2020-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/protocol/data.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_encode_req_handshake_request);

/**
 * Test the basics of the encoding.
 */
TEST(basics)
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
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_options_init(
                    &suite, &alloc_opts, VCCRYPT_SUITE_VELO_V1));

    /* create a buffer for holding the key nonce. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
                    &suite, &client_key_nonce));
    /* set the key nonce value. */
    memset(client_key_nonce.data, 0xFE, client_key_nonce.size);

    /* create a buffer for holding the challenge nonce. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_suite_buffer_init_for_cipher_key_agreement_nonce(
                    &suite, &client_challenge_nonce));
    /* set the challenge nonce. */
    memset(client_challenge_nonce.data, 0xEC, client_challenge_nonce.size);

    /* PRECONDITION: output should have a null data and 0 size. */
    out.data = nullptr;
    out.size = 0U;

    /* encoding the handshake request should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vcblockchain_protocol_encode_req_handshake_request(
                    &out, &suite, EXPECTED_OFFSET, &client_id,
                    &client_key_nonce, &client_challenge_nonce));

    /* the out data and size should be set. */
    TEST_ASSERT(nullptr != out.data);
    TEST_ASSERT(0U != out.size);

    /* get a byte pointer to the output buffer. */
    const uint8_t* buf = (const uint8_t*)out.data;
    size_t size = out.size;

    /* the first four bytes should be the request id. */
    uint32_t net_request;
    TEST_ASSERT(size >= sizeof(net_request));
    memcpy(&net_request, buf, sizeof(net_request));
    TEST_EXPECT(PROTOCOL_REQ_ID_HANDSHAKE_INITIATE == ntohl(net_request));
    buf += sizeof(net_request); size -= sizeof(net_request);

    /* then comes the offset. */
    uint32_t net_offset;
    TEST_ASSERT(size >= sizeof(net_offset));
    memcpy(&net_offset, buf, sizeof(net_offset));
    TEST_EXPECT(EXPECTED_OFFSET == ntohl(net_offset));
    buf += sizeof(net_offset); size -= sizeof(net_offset);

    /* then the protocol version. */
    uint32_t net_protocol_version;
    TEST_ASSERT(size >= sizeof(net_protocol_version));
    memcpy(&net_protocol_version, buf, sizeof(net_protocol_version));
    TEST_EXPECT(PROTOCOL_VERSION_0_1_DEMO == ntohl(net_protocol_version));
    buf += sizeof(net_protocol_version); size -= sizeof(net_protocol_version);

    /* the the crypto suite. */
    uint32_t net_crypto_suite;
    TEST_ASSERT(size >= sizeof(net_crypto_suite));
    memcpy(&net_crypto_suite, buf, sizeof(net_crypto_suite));
    TEST_EXPECT(VCCRYPT_SUITE_VELO_V1 == ntohl(net_crypto_suite));
    buf += sizeof(net_crypto_suite); size -= sizeof(net_crypto_suite);

    /* then the client id. */
    TEST_ASSERT(size >= sizeof(client_id));
    TEST_EXPECT(0 == memcmp(buf, &client_id, sizeof(client_id)));
    buf += sizeof(client_id); size -= sizeof(client_id);

    /* then the key nonce. */
    TEST_ASSERT(size >= client_key_nonce.size);
    TEST_EXPECT(0 == memcmp(buf, client_key_nonce.data, client_key_nonce.size));
    buf += client_key_nonce.size; size -= client_key_nonce.size;

    /* finally, the challenge nonce. */
    TEST_ASSERT(client_challenge_nonce.size == size);
    TEST_EXPECT(
        0
            == memcmp(
                    buf, client_challenge_nonce.data,
                    client_challenge_nonce.size));

    /* clean up. */
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&client_key_nonce);
    dispose((disposable_t*)&client_challenge_nonce);
    dispose((disposable_t*)&suite);
    dispose((disposable_t*)&alloc_opts);
}
