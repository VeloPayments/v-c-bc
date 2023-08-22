/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_req_transaction_submit.cpp
 *
 * Unit tests for encoding the transaction submit request.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

/* DISABLED GTEST */
#if 0

using namespace std;

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(test_vcblockchain_protocol_encode_req_transaction_submit, parameter_check)
{
    const uint32_t EXPECTED_OFFSET = 97;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    const vpr_uuid EXPECTED_TXN_ID = { .data = {
        0xca, 0x14, 0x0d, 0x1e, 0x5b, 0xcf, 0x47, 0xa9,
        0xab, 0xf7, 0xbc, 0xd8, 0xfa, 0xdb, 0x48, 0x27 }};
    const vpr_uuid EXPECTED_ARTIFACT_ID = { .data = {
        0x22, 0x48, 0xfc, 0x5b, 0x3c, 0x36, 0x45, 0x01,
        0x9a, 0x34, 0x1d, 0x56, 0xad, 0xbe, 0xd7, 0xd4 }};
    const uint8_t EXPECTED_CERT[4] = { 0x07, 0x08, 0x09, 0x0a };
    const size_t EXPECTED_CERT_SIZE = sizeof(EXPECTED_CERT);

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* This method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_transaction_submit(
            nullptr, &alloc_opts, EXPECTED_OFFSET, &EXPECTED_TXN_ID,
            &EXPECTED_ARTIFACT_ID, EXPECTED_CERT, EXPECTED_CERT_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_transaction_submit(
            &buffer, nullptr, EXPECTED_OFFSET, &EXPECTED_TXN_ID,
            &EXPECTED_ARTIFACT_ID, EXPECTED_CERT, EXPECTED_CERT_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_transaction_submit(
            &buffer, &alloc_opts, EXPECTED_OFFSET, nullptr,
            &EXPECTED_ARTIFACT_ID, EXPECTED_CERT, EXPECTED_CERT_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_transaction_submit(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &EXPECTED_TXN_ID,
            nullptr, EXPECTED_CERT, EXPECTED_CERT_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_req_transaction_submit(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &EXPECTED_TXN_ID,
            &EXPECTED_ARTIFACT_ID, nullptr, EXPECTED_CERT_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * If valid parameters are provided, this method encodes a request message.
 */
TEST(test_vcblockchain_protocol_encode_req_transaction_submit, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 97;
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;
    const vpr_uuid EXPECTED_TXN_ID = { .data = {
        0xca, 0x14, 0x0d, 0x1e, 0x5b, 0xcf, 0x47, 0xa9,
        0xab, 0xf7, 0xbc, 0xd8, 0xfa, 0xdb, 0x48, 0x27 }};
    const vpr_uuid EXPECTED_ARTIFACT_ID = { .data = {
        0x22, 0x48, 0xfc, 0x5b, 0x3c, 0x36, 0x45, 0x01,
        0x9a, 0x34, 0x1d, 0x56, 0xad, 0xbe, 0xd7, 0xd4 }};
    const uint8_t EXPECTED_CERT[4] = { 0x07, 0x08, 0x09, 0x0a };
    const size_t EXPECTED_CERT_SIZE = sizeof(EXPECTED_CERT);

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: set the buffer to null / 0. */
    buffer.data = nullptr; buffer.size = 0;

    /* This method populates the message buffer on success. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_req_transaction_submit(
            &buffer, &alloc_opts, EXPECTED_OFFSET, &EXPECTED_TXN_ID,
            &EXPECTED_ARTIFACT_ID, EXPECTED_CERT, EXPECTED_CERT_SIZE));

    /* compute the message size. */
    size_t message_size = 2 * sizeof(uint32_t) + 2 * 16 + EXPECTED_CERT_SIZE;

    /* the buffer has been initialized. */
    ASSERT_NE(nullptr, buffer.data);
    ASSERT_EQ(message_size, buffer.size);

    /* verify that the request id and offset is set correctly. */
    const uint32_t* u32arr = (const uint32_t*)buffer.data;
    EXPECT_EQ(htonl(PROTOCOL_REQ_ID_TRANSACTION_SUBMIT), u32arr[0]);
    EXPECT_EQ(htonl(EXPECTED_OFFSET), u32arr[1]);

    /* verify that the transaction id and artifact id is set correctly. */
    const uint8_t* barr = (const uint8_t*)&(u32arr[2]);
    EXPECT_EQ(0, memcmp(barr, &EXPECTED_TXN_ID, 16));
    EXPECT_EQ(0, memcmp(barr + 16, &EXPECTED_ARTIFACT_ID, 16));
    EXPECT_EQ(0, memcmp(barr + 32, EXPECTED_CERT, EXPECTED_CERT_SIZE));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
#endif
