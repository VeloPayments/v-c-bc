/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_resp_block_get.cpp
 *
 * Unit tests for encoding the block get response.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
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
TEST(test_vcblockchain_protocol_encode_resp_block_get, parameter_checks)
{
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    const vpr_uuid EXPECTED_BLOCK_ID = { .data = {
        0xef, 0xc9, 0x5b, 0x49, 0x25, 0x97, 0x4d, 0x0f,
        0x9b, 0x55, 0x09, 0x97, 0xf3, 0xea, 0x85, 0x37 } };
    const vpr_uuid EXPECTED_PREV_BLOCK_ID = { .data = {
        0x36, 0x9b, 0xc4, 0x39, 0x5e, 0x0e, 0x40, 0x71,
        0x9d, 0x00, 0xee, 0x36, 0x10, 0x85, 0x82, 0x2d } };
    const vpr_uuid EXPECTED_NEXT_BLOCK_ID = { .data = {
        0xa6, 0x1a, 0x14, 0xae, 0x93, 0xdb, 0x4d, 0x98,
        0x89, 0xe5, 0x3a, 0xb7, 0xd3, 0x72, 0x18, 0x4e } };
    const vpr_uuid EXPECTED_FIRST_TXN_ID = { .data = {
        0xd6, 0x7b, 0x54, 0x81, 0xc4, 0x78, 0x40, 0xd8,
        0xba, 0x77, 0x89, 0x49, 0x56, 0x1d, 0x85, 0x6d } };
    const uint64_t EXPECTED_BLOCK_HEIGHT = 71;
    const uint64_t EXPECTED_SER_BLOCK_CERT_SIZE = 3;
    const uint8_t EXPECTED_BLOCK_CERT[3] = { 0x11, 0x12, 0x13 };
    const size_t EXPECTED_BLOCK_CERT_SIZE = sizeof(EXPECTED_BLOCK_CERT);

    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* this method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_block_get(
            nullptr, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_BLOCK_ID, &EXPECTED_PREV_BLOCK_ID,
            &EXPECTED_NEXT_BLOCK_ID, &EXPECTED_FIRST_TXN_ID,
            EXPECTED_BLOCK_HEIGHT, EXPECTED_SER_BLOCK_CERT_SIZE,
            EXPECTED_BLOCK_CERT, EXPECTED_BLOCK_CERT_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_block_get(
            &buffer, nullptr, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_BLOCK_ID, &EXPECTED_PREV_BLOCK_ID,
            &EXPECTED_NEXT_BLOCK_ID, &EXPECTED_FIRST_TXN_ID,
            EXPECTED_BLOCK_HEIGHT, EXPECTED_SER_BLOCK_CERT_SIZE,
            EXPECTED_BLOCK_CERT, EXPECTED_BLOCK_CERT_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_block_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            nullptr, &EXPECTED_PREV_BLOCK_ID,
            &EXPECTED_NEXT_BLOCK_ID, &EXPECTED_FIRST_TXN_ID,
            EXPECTED_BLOCK_HEIGHT, EXPECTED_SER_BLOCK_CERT_SIZE,
            EXPECTED_BLOCK_CERT, EXPECTED_BLOCK_CERT_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_block_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_BLOCK_ID, nullptr,
            &EXPECTED_NEXT_BLOCK_ID, &EXPECTED_FIRST_TXN_ID,
            EXPECTED_BLOCK_HEIGHT, EXPECTED_SER_BLOCK_CERT_SIZE,
            EXPECTED_BLOCK_CERT, EXPECTED_BLOCK_CERT_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_block_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_BLOCK_ID, &EXPECTED_PREV_BLOCK_ID,
            nullptr, &EXPECTED_FIRST_TXN_ID,
            EXPECTED_BLOCK_HEIGHT, EXPECTED_SER_BLOCK_CERT_SIZE,
            EXPECTED_BLOCK_CERT, EXPECTED_BLOCK_CERT_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_block_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_BLOCK_ID, &EXPECTED_PREV_BLOCK_ID,
            &EXPECTED_NEXT_BLOCK_ID, nullptr,
            EXPECTED_BLOCK_HEIGHT, EXPECTED_SER_BLOCK_CERT_SIZE,
            EXPECTED_BLOCK_CERT, EXPECTED_BLOCK_CERT_SIZE));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_block_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_BLOCK_ID, &EXPECTED_PREV_BLOCK_ID,
            &EXPECTED_NEXT_BLOCK_ID, &EXPECTED_FIRST_TXN_ID,
            EXPECTED_BLOCK_HEIGHT, EXPECTED_SER_BLOCK_CERT_SIZE,
            nullptr, EXPECTED_BLOCK_CERT_SIZE));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/**
 * This method should encode the response message.
 */
TEST(test_vcblockchain_protocol_encode_resp_block_get, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    const vpr_uuid EXPECTED_BLOCK_ID = { .data = {
        0xef, 0xc9, 0x5b, 0x49, 0x25, 0x97, 0x4d, 0x0f,
        0x9b, 0x55, 0x09, 0x97, 0xf3, 0xea, 0x85, 0x37 } };
    const vpr_uuid EXPECTED_PREV_BLOCK_ID = { .data = {
        0x36, 0x9b, 0xc4, 0x39, 0x5e, 0x0e, 0x40, 0x71,
        0x9d, 0x00, 0xee, 0x36, 0x10, 0x85, 0x82, 0x2d } };
    const vpr_uuid EXPECTED_NEXT_BLOCK_ID = { .data = {
        0xa6, 0x1a, 0x14, 0xae, 0x93, 0xdb, 0x4d, 0x98,
        0x89, 0xe5, 0x3a, 0xb7, 0xd3, 0x72, 0x18, 0x4e } };
    const vpr_uuid EXPECTED_FIRST_TXN_ID = { .data = {
        0xd6, 0x7b, 0x54, 0x81, 0xc4, 0x78, 0x40, 0xd8,
        0xba, 0x77, 0x89, 0x49, 0x56, 0x1d, 0x85, 0x6d } };
    const uint64_t EXPECTED_BLOCK_HEIGHT = 71;
    const uint64_t EXPECTED_SER_BLOCK_CERT_SIZE = 3;
    const uint8_t EXPECTED_BLOCK_CERT[3] = { 0x11, 0x12, 0x13 };
    const size_t EXPECTED_BLOCK_CERT_SIZE = sizeof(EXPECTED_BLOCK_CERT);

    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: the buffer is nulled out. */
    buffer.data = nullptr; buffer.size = 0;

    /* this method performs null checks on pointer parameters. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_resp_block_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_BLOCK_ID, &EXPECTED_PREV_BLOCK_ID,
            &EXPECTED_NEXT_BLOCK_ID, &EXPECTED_FIRST_TXN_ID,
            EXPECTED_BLOCK_HEIGHT, EXPECTED_SER_BLOCK_CERT_SIZE,
            EXPECTED_BLOCK_CERT, EXPECTED_BLOCK_CERT_SIZE));

    /* the buffer should not be null. */
    ASSERT_NE(nullptr, buffer.data);
    ASSERT_EQ(
        3 * sizeof(uint32_t) + 4 * 16 + 2 * 8 + EXPECTED_BLOCK_CERT_SIZE,
        buffer.size);

    /* check the inteeger values. */
    uint32_t* uarr = (uint32_t*)buffer.data;
    EXPECT_EQ(htonl(PROTOCOL_REQ_ID_BLOCK_BY_ID_GET), uarr[0]);
    EXPECT_EQ(htonl(EXPECTED_OFFSET), uarr[1]);
    EXPECT_EQ(htonl(EXPECTED_STATUS), uarr[2]);

    /* check the uuids. */
    uint8_t* barr = (uint8_t*)(uarr + 3);
    EXPECT_EQ(0, memcmp(barr,      &EXPECTED_BLOCK_ID, 16));
    EXPECT_EQ(0, memcmp(barr + 16, &EXPECTED_PREV_BLOCK_ID, 16));
    EXPECT_EQ(0, memcmp(barr + 32, &EXPECTED_NEXT_BLOCK_ID, 16));
    EXPECT_EQ(0, memcmp(barr + 48, &EXPECTED_FIRST_TXN_ID, 16));

    /* check the 64-bit values. */
    uint64_t net_block_height = htonll(EXPECTED_BLOCK_HEIGHT);
    EXPECT_EQ(0, memcmp(barr + 64, &net_block_height, 8));
    uint64_t net_ser_block_size = htonll(EXPECTED_SER_BLOCK_CERT_SIZE);
    EXPECT_EQ(0, memcmp(barr + 72, &net_ser_block_size, 8));

    /* check the block certificate. */
    EXPECT_EQ(
        0,
        memcmp(barr + 80, EXPECTED_BLOCK_CERT, EXPECTED_SER_BLOCK_CERT_SIZE));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
