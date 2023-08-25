/**
 * \file
 * test/protocol/test_vcblockchain_protocol_encode_resp_artifact_last_txn_id_get.cpp
 *
 * Unit tests for encoding the artifact last txn id get response.
 *
 * \copyright 2021-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_encode_resp_artifact_last_txn_id_get);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameters)
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
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_resp_artifact_last_txn_id_get(
                    nullptr, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &EXPECTED_FIRST_TXN_ID));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_resp_artifact_last_txn_id_get(
                    &buffer, nullptr, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &EXPECTED_FIRST_TXN_ID));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_encode_resp_artifact_last_txn_id_get(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    nullptr));

    /* clean up. */
    dispose((disposable_t*)&alloc_opts);
}

/* This method should encode the response message. */
TEST(happy_path)
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
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_artifact_last_txn_id_get(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &EXPECTED_ARTIFACT_ID));

    /* the buffer should not be null. */
    TEST_ASSERT(nullptr != buffer.data);
    TEST_ASSERT(3 * sizeof(uint32_t) + 16 == buffer.size);

    /* check the integer values. */
    uint32_t* uarr = (uint32_t*)buffer.data;
    TEST_EXPECT(htonl(PROTOCOL_REQ_ID_ARTIFACT_LAST_TXN_BY_ID_GET) == uarr[0]);
    TEST_EXPECT(htonl(EXPECTED_STATUS) == uarr[1]);
    TEST_EXPECT(htonl(EXPECTED_OFFSET) == uarr[2]);

    /* check the uuid. */
    uint8_t* barr = (uint8_t*)buffer.data;
    barr += 3 * sizeof(uint32_t);
    TEST_EXPECT(
        0 == memcmp(barr, &EXPECTED_ARTIFACT_ID, sizeof(EXPECTED_ARTIFACT_ID)));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
