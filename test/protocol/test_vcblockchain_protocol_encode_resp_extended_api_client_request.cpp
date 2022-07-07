/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_resp_extended_api_client_request.cpp
 *
 * Unit tests for encoding an extended api client request response.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <vcblockchain/byteswap.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(
    test_vcblockchain_protocol_encode_resp_extended_api_client_request,
    parameter_checks)
{
    const uint64_t EXPECTED_OFFSET = 66;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t client_enc_pubkey;
    vccrypt_buffer_t client_sign_pubkey;
    vccrypt_buffer_t request_body;
    const vpr_uuid client_id = { .data = {
        0x39, 0xb9, 0x97, 0x82, 0x0e, 0x94, 0x4c, 0xf5,
        0xb3, 0xf2, 0x81, 0xba, 0x7b, 0x89, 0x68, 0x2b } };
    const vpr_uuid verb_id = { .data = {
        0xd9, 0xed, 0x85, 0x9b, 0xa0, 0x50, 0x49, 0xb7,
        0xbe, 0xc5, 0xdb, 0x17, 0xf0, 0x7a, 0xf4, 0xdc } };

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* this method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_extended_api_client_request(
            nullptr, &alloc_opts, EXPECTED_OFFSET, &client_id,
            &verb_id, &client_enc_pubkey, &client_sign_pubkey, &request_body));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_extended_api_client_request(
            &buffer, nullptr, EXPECTED_OFFSET, &client_id,
            &verb_id, &client_enc_pubkey, &client_sign_pubkey, &request_body));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_extended_api_client_request(
            &buffer, &alloc_opts, EXPECTED_OFFSET, nullptr,
            &verb_id, &client_enc_pubkey, &client_sign_pubkey, &request_body));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_extended_api_client_request(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &client_id,
            nullptr, &client_enc_pubkey, &client_sign_pubkey, &request_body));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_extended_api_client_request(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &client_id,
            &verb_id, nullptr, &client_sign_pubkey, &request_body));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_extended_api_client_request(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &client_id,
            &verb_id, &client_enc_pubkey, nullptr, &request_body));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_extended_api_client_request(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &client_id,
            &verb_id, &client_enc_pubkey, &client_sign_pubkey, nullptr));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method should encode the response message.
 */
TEST(
    test_vcblockchain_protocol_encode_resp_extended_api_client_request,
    happy_path)
{
    const uint64_t EXPECTED_OFFSET = 66;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t client_enc_pubkey;
    vccrypt_buffer_t client_sign_pubkey;
    vccrypt_buffer_t request_body;
    const vpr_uuid client_id = { .data = {
        0x39, 0xb9, 0x97, 0x82, 0x0e, 0x94, 0x4c, 0xf5,
        0xb3, 0xf2, 0x81, 0xba, 0x7b, 0x89, 0x68, 0x2b } };
    const vpr_uuid verb_id = { .data = {
        0xd9, 0xed, 0x85, 0x9b, 0xa0, 0x50, 0x49, 0xb7,
        0xbe, 0xc5, 0xdb, 0x17, 0xf0, 0x7a, 0xf4, 0xdc } };

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a dummy request body buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&request_body, &alloc_opts, 32));
    memset(request_body.data, 0xa7, request_body.size);

    /* create a dummy client encryption pubkey buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&client_enc_pubkey, &alloc_opts, 32));
    memset(client_enc_pubkey.data, 0x02, client_enc_pubkey.size);

    /* create a dummy client signing pubkey buffer. */
    ASSERT_EQ(
        VCCRYPT_STATUS_SUCCESS,
        vccrypt_buffer_init(&client_sign_pubkey, &alloc_opts, 64));
    memset(client_sign_pubkey.data, 0x02, client_sign_pubkey.size);

    /* precondition: buffer is nulled out. */
    memset(&buffer, 0, sizeof(buffer));

    /* this method should succeed. */
    EXPECT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_resp_extended_api_client_request(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &client_id,
            &verb_id, &client_enc_pubkey, &client_sign_pubkey, &request_body));

    /* the buffer should not be null. */
    ASSERT_NE(nullptr, buffer.data);
    /* the buffer should be the right size. */
    size_t expected_buffer_size =
        3 * sizeof(uint32_t)
      + sizeof(uint64_t) /* offset. */
      + sizeof(client_id)
      + sizeof(verb_id)
      + client_enc_pubkey.size
      + client_sign_pubkey.size
      + request_body.size;
    ASSERT_EQ(expected_buffer_size, buffer.size);

    /* make working with this buffer easier. */
    const uint8_t* barr = (const uint8_t*)buffer.data;

    /* the request id should be correct. */
    uint32_t net_request_id;
    memcpy(&net_request_id, barr, sizeof(net_request_id));
    barr += sizeof(net_request_id);
    EXPECT_EQ(PROTOCOL_REQ_ID_EXTENDED_API_CLIENTREQ, ntohl(net_request_id));

    /* the offset should be correct. */
    uint64_t net_offset;
    memcpy(&net_offset, barr, sizeof(net_offset));
    barr += sizeof(net_offset);
    EXPECT_EQ(EXPECTED_OFFSET, ntohll(net_offset));

    /* the client encryption pubkey size should be correct. */
    uint32_t net_enc_key_size;
    memcpy(&net_enc_key_size, barr, sizeof(net_enc_key_size));
    barr += sizeof(net_enc_key_size);
    EXPECT_EQ(client_enc_pubkey.size, ntohl(net_enc_key_size));

    /* the client signing pubkey size should be correct. */
    uint32_t net_sign_key_size;
    memcpy(&net_sign_key_size, barr, sizeof(net_sign_key_size));
    barr += sizeof(net_sign_key_size);
    EXPECT_EQ(client_sign_pubkey.size, ntohl(net_sign_key_size));
 
    /* the client id should be correct. */
    EXPECT_EQ(0, memcmp(&client_id, barr, sizeof(client_id)));
    barr += sizeof(client_id);

    /* the verb id should be correct. */
    EXPECT_EQ(0, memcmp(&verb_id, barr, sizeof(verb_id)));
    barr += sizeof(verb_id);

    /* the encryption pubkey should be correct. */
    EXPECT_EQ(0, memcmp(client_enc_pubkey.data, barr, client_enc_pubkey.size));
    barr += client_enc_pubkey.size;

    /* the signing pubkey should be correct. */
    EXPECT_EQ(
        0, memcmp(client_sign_pubkey.data, barr, client_sign_pubkey.size));
    barr += client_sign_pubkey.size;

    /* the request body should be correct. */
    EXPECT_EQ(0, memcmp(request_body.data, barr, request_body.size));
    barr += request_body.size;

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&request_body);
    dispose((disposable_t*)&client_enc_pubkey);
    dispose((disposable_t*)&client_sign_pubkey);
    dispose((disposable_t*)&alloc_opts);
}
