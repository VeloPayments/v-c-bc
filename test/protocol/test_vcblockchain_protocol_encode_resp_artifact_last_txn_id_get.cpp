/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_resp_artifact_last_txn_id_get.cpp
 *
 * Unit tests for encoding the artifact last txn id get response.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
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
TEST(test_vcblockchain_protocol_encode_resp_artifact_last_txn_id_get, parameters)
{
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    const vpr_uuid EXPECTED_FIRST_TXN_ID = { .data = {
        0xef, 0xc9, 0x5b, 0x49, 0x25, 0x97, 0x4d, 0x0f,
        0x9b, 0x55, 0x09, 0x97, 0xf3, 0xea, 0x85, 0x37 } };
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* this method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_artifact_last_txn_id_get(
            nullptr, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_FIRST_TXN_ID));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_artifact_last_txn_id_get(
            &buffer, nullptr, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_FIRST_TXN_ID));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_protocol_encode_resp_artifact_last_txn_id_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            nullptr));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/* This method should encode the response message. */
TEST(test_vcblockchain_protocol_encode_resp_artifact_last_txn_id_get, happy_path)
{
    const uint32_t EXPECTED_OFFSET = 26;
    const uint32_t EXPECTED_STATUS = 11;
    const vpr_uuid EXPECTED_ARTIFACT_ID = { .data = {
        0xef, 0xc9, 0x5b, 0x49, 0x25, 0x97, 0x4d, 0x0f,
        0x9b, 0x55, 0x09, 0x97, 0xf3, 0xea, 0x85, 0x37 } };
    allocator_options_t alloc_opts;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* precondition: buffer is nulled out. */
    buffer.data = nullptr; buffer.size = 0;

    /* this method should succeed. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        vcblockchain_protocol_encode_resp_artifact_last_txn_id_get(
            &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
            &EXPECTED_ARTIFACT_ID));

    /* the buffer should not be null. */
    ASSERT_NE(nullptr, buffer.data);
    ASSERT_EQ(3 * sizeof(uint32_t) + 16, buffer.size);

    /* check the integer values. */
    uint32_t* uarr = (uint32_t*)buffer.data;
    EXPECT_EQ(htonl(PROTOCOL_REQ_ID_ARTIFACT_LAST_TXN_BY_ID_GET), uarr[0]);
    EXPECT_EQ(htonl(EXPECTED_STATUS), uarr[1]);
    EXPECT_EQ(htonl(EXPECTED_OFFSET), uarr[2]);

    /* check the uuid. */
    uint8_t* barr = (uint8_t*)buffer.data;
    barr += 3 * sizeof(uint32_t);
    EXPECT_EQ(
        0, memcmp(barr, &EXPECTED_ARTIFACT_ID, sizeof(EXPECTED_ARTIFACT_ID)));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
#endif
