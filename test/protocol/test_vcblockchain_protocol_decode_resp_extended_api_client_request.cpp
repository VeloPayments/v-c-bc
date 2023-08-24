/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_resp_extended_api_client_request.cpp
 *
 * Unit tests for decoding an extended api client request response.
 *
 * \copyright 2022-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_decode_resp_extended_api_client_request);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_checks)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_resp_extended_api_client_request resp;
    allocator_options_t alloc_opts;

    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_extended_api_client_request(
                    nullptr, &alloc_opts, EXPECTED_PAYLOAD,
                    EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_extended_api_client_request(
                    &resp, nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_extended_api_client_request(
                    &resp, &alloc_opts, nullptr, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method should check the payload size to make sure it is correct.
 */
TEST(payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_resp_extended_api_client_request resp;
    allocator_options_t alloc_opts;

    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_extended_api_client_request(
                    &resp, &alloc_opts, EXPECTED_PAYLOAD,
                    EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method can decode a properly encoded response message.
 */
TEST(happy_path)
{
    const uint64_t EXPECTED_OFFSET = 93;
    protocol_resp_extended_api_client_request resp;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    vccrypt_buffer_t client_enc_pubkey;
    vccrypt_buffer_t client_sign_pubkey;
    vccrypt_buffer_t request_body;
    const vpr_uuid client_id = { .data = {
        0x3f, 0x90, 0x79, 0x2c, 0xb8, 0x1f, 0x40, 0x19,
        0x97, 0xaf, 0xe2, 0xe6, 0x00, 0xe0, 0xc3, 0x24 } };
    const vpr_uuid verb_id = { .data = {
        0x3d, 0x2b, 0x20, 0xca, 0x1c, 0x48, 0x4e, 0xca,
        0x99, 0x9e, 0x88, 0x37, 0x31, 0x12, 0xf2, 0xca } };

    malloc_allocator_options_init(&alloc_opts);

    /* create dummy encryption pubkey. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&client_enc_pubkey, &alloc_opts, 32));
    memset(client_enc_pubkey.data, 0x0c, client_enc_pubkey.size);

    /* create dummy signing pubkey. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&client_sign_pubkey, &alloc_opts, 64));
    memset(client_sign_pubkey.data, 0xc0, client_sign_pubkey.size);

    /* create dummy request body. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vccrypt_buffer_init(&request_body, &alloc_opts, 32));
    memset(request_body.data, 0x11, request_body.size);

    /* we can encode a message. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_extended_api_client_request(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, &client_id, &verb_id,
                    &client_enc_pubkey, &client_sign_pubkey, &request_body));

    /* precondition: the response buffer is zeroed out. */
    memset(&resp, 0, sizeof(resp));

    /* we can decode this message. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_decode_resp_extended_api_client_request(
                    &resp, &alloc_opts, buffer.data, buffer.size));

    /* the request id is set correctly. */
    TEST_EXPECT(PROTOCOL_REQ_ID_EXTENDED_API_CLIENTREQ == resp.request_id);
    /* the offset is set correctly. */
    TEST_EXPECT(EXPECTED_OFFSET == resp.offset);
    /* the client id is set correctly. */
    TEST_EXPECT(0 == memcmp(&client_id, &resp.client_id, sizeof(client_id)));
    /* the verb id is set correctly. */
    TEST_EXPECT(0 == memcmp(&verb_id, &resp.verb_id, sizeof(verb_id)));
    /* the client encryption pubkey buffer is not null. */
    TEST_ASSERT(nullptr != resp.client_enc_pubkey.data);
    /* the client encryption pubkey size is correct. */
    TEST_ASSERT(client_enc_pubkey.size == resp.client_enc_pubkey.size);
    /* the client encryption key matches. */
    TEST_EXPECT(
        0
            == memcmp(
                    client_enc_pubkey.data, resp.client_enc_pubkey.data,
                    client_enc_pubkey.size));
    /* the client signing pubkey buffer is not null. */
    TEST_ASSERT(nullptr != resp.client_sign_pubkey.data);
    /* the client signing pubkey size is correct. */
    TEST_ASSERT(client_sign_pubkey.size == resp.client_sign_pubkey.size);
    /* the client signing key matches. */
    TEST_EXPECT(
        0
            == memcmp(
                    client_sign_pubkey.data, resp.client_sign_pubkey.data,
                    client_sign_pubkey.size));
    /* the request body buffer is not null. */
    TEST_ASSERT(nullptr != resp.request_body.data);
    /* the request body size is correct. */
    TEST_ASSERT(request_body.size == resp.request_body.size);
    /* the request body matches. */
    TEST_EXPECT(
        0
            == memcmp(
                    request_body.data, resp.request_body.data,
                    request_body.size));

    /* clean up. */
    dispose((disposable_t*)&resp);
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&client_enc_pubkey);
    dispose((disposable_t*)&client_sign_pubkey);
    dispose((disposable_t*)&request_body);
    dispose((disposable_t*)&alloc_opts);
}
