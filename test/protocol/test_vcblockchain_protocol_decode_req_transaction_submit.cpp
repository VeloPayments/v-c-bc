/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_req_transaction_submit.cpp
 *
 * Unit tests for decoding the transaction submit request.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

/* DISABLED GTEST */
#if 0

using namespace std;

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(test_vcblockchain_protocol_decode_req_transaction_submit, parameter_check)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    allocator_options_t alloc_opts;
    protocol_req_transaction_submit req;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_transaction_submit(
            nullptr, &alloc_opts, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_transaction_submit(
            &req, nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_transaction_submit(
            &req, &alloc_opts, nullptr, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method checks the payload size to make sure it's at least large enough
 * to hold the header data.
 */
TEST(test_vcblockchain_protocol_decode_req_transaction_submit, payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    allocator_options_t alloc_opts;
    protocol_req_transaction_submit req;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_decode_req_transaction_submit(
            &req, &alloc_opts, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method can decode a properly encoded request message.
 */
TEST(test_vcblockchain_protocol_decode_req_transaction_submit, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 88;
    const vpr_uuid EXPECTED_TXN_ID = { .data = {
        0x1f, 0x8c, 0x34, 0x1c, 0x63, 0xe2, 0x46, 0x90,
        0xba, 0x45, 0x9a, 0x35, 0xd4, 0xec, 0xbc, 0x3c } };
    const vpr_uuid EXPECTED_ARTIFACT_ID = { .data = {
        0xce, 0x25, 0xa1, 0x53, 0xb9, 0x4d, 0x46, 0xcf,
        0xab, 0x18, 0xc2, 0x57, 0x5c, 0x8c, 0x69, 0x13 } };
    const uint8_t EXPECTED_CERT[4] = { 0x03, 0x04, 0x05, 0x06 };
    const size_t EXPECTED_CERT_SIZE = sizeof(EXPECTED_CERT);
    allocator_options_t alloc_opts;
    protocol_req_transaction_submit req;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* we can encode a message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_transaction_submit(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &EXPECTED_TXN_ID,
            &EXPECTED_ARTIFACT_ID, EXPECTED_CERT, EXPECTED_CERT_SIZE));

    /* precondition: the request buffer is zeroed out. */
    memset(&req, 0, sizeof(req));

    /* we can decode this message. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_decode_req_transaction_submit(
            &req, &alloc_opts, buffer.data, buffer.size));

    /* the request id is set correctly. */
    EXPECT_EQ(PROTOCOL_REQ_ID_TRANSACTION_SUBMIT, req.request_id);
    /* the offset id is set correctly. */
    EXPECT_EQ(EXPECTED_OFFSET, req.offset);
    /* the transaction id is set correctly. */
    EXPECT_EQ(0, memcmp(&req.txn_id, &EXPECTED_TXN_ID, 16));
    /* the artifact id is set correctly. */
    EXPECT_EQ(0, memcmp(&req.artifact_id, &EXPECTED_ARTIFACT_ID, 16));
    /* the certificate is set correctly. */
    ASSERT_EQ(EXPECTED_CERT_SIZE, req.cert.size);
    EXPECT_EQ(0, memcmp(req.cert.data, EXPECTED_CERT, EXPECTED_CERT_SIZE));

    /* clean up. */
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
#endif
