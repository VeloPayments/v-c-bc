/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_req_txn_get.cpp
 *
 * Unit tests for decoding the txn get request.
 *
 * \copyright 2021-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_decode_req_txn_get);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameter_check)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_txn_get req;

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_txn_get(
                    nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_txn_get(
                    &req, nullptr, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method should verify the payload size.
 */
TEST(payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_req_txn_get req;

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_req_txn_get(
                    &req, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method can decode a properly encoded request message.
 */
TEST(happy_path)
{
    const uint32_t EXPECTED_OFFSET = 121;
    const vpr_uuid EXPECTED_TXN_ID = { .data = {
        0x97, 0x23, 0x0f, 0x7e, 0xa7, 0xbd, 0x45, 0x68,
        0x85, 0xc4, 0xe1, 0x12, 0x97, 0x07, 0xdc, 0x75 } };
    allocator_options_t alloc_opts;
    protocol_req_txn_get req;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* we can encode a message. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_req_txn_get(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, &EXPECTED_TXN_ID));

    /* precondition: the request buffer is zeroed out. */
    memset(&req, 0, sizeof(req));

    /* we can decode this message. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_decode_req_txn_get(
                    &req, buffer.data, buffer.size));

    /* the request id is set correctly. */
    TEST_EXPECT(PROTOCOL_REQ_ID_TRANSACTION_BY_ID_GET == req.request_id);
    /* the offset is set correctly. */
    TEST_EXPECT(EXPECTED_OFFSET == req.offset);
    /* the block id is set correctly. */
    TEST_EXPECT(0 == memcmp(&req.txn_id, &EXPECTED_TXN_ID, 16));

    /* clean up. */
    dispose((disposable_t*)&req);
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&alloc_opts);
}
