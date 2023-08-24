/**
 * \file
 * test/protocol/test_vcblockchain_protocol_decode_resp_block_next_id_get.cpp
 *
 * Unit tests for decoding the block next id get response.
 *
 * \copyright 2020-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/protocol/serialization.h>
#include <vpr/allocator/malloc_allocator.h>

using namespace std;

TEST_SUITE(test_vcblockchain_protocol_decode_resp_block_next_id_get);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameters)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_resp_block_next_id_get resp;

    /* This method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_block_next_id_get(
                    nullptr, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_block_next_id_get(
                    &resp, nullptr, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method should check the payload size to make sure it is correct.
 */
TEST(payload_size)
{
    const uint8_t EXPECTED_PAYLOAD[4] = { 0x00, 0x01, 0x02, 0x03 };
    size_t EXPECTED_PAYLOAD_SIZE = sizeof(EXPECTED_PAYLOAD);
    protocol_resp_block_next_id_get resp;

    /* This method performs a payload size check. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_protocol_decode_resp_block_next_id_get(
                    &resp, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SIZE));
}

/**
 * This method can decode a properly encoded response message.
 */
TEST(happy_path)
{
    const uint32_t EXPECTED_OFFSET = 12;
    const uint32_t EXPECTED_STATUS = 77;
    const vpr_uuid EXPECTED_NEXT_BLOCK_ID = { .data = {
        0x79, 0x40, 0xfb, 0x8d, 0xe9, 0x4c, 0x45, 0xf0,
        0x93, 0x28, 0x95, 0x09, 0x8c, 0xae, 0xa7, 0xf6 } };
    allocator_options_t alloc_opts;
    protocol_resp_block_next_id_get resp;
    vccrypt_buffer_t buffer;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* we can encode a message. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_block_next_id_get(
                    &buffer, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS,
                    &EXPECTED_NEXT_BLOCK_ID));

    /* precondition: the response buffer is zeroed out. */
    memset(&resp, 0, sizeof(resp));

    /* we can decode this message. */
    TEST_ASSERT(
        VCBLOCKCHAIN_STATUS_SUCCESS
            == vcblockchain_protocol_decode_resp_block_next_id_get(
                    &resp, buffer.data, buffer.size));

    /* the request id is set correctly. */
    TEST_EXPECT(PROTOCOL_REQ_ID_BLOCK_ID_GET_NEXT == resp.request_id);
    /* the offset is set correctly. */
    TEST_EXPECT(EXPECTED_OFFSET == resp.offset);
    /* the status is set correctly. */
    TEST_EXPECT(EXPECTED_STATUS == resp.status);
    /* the block id is set correctly. */
    TEST_EXPECT(0 == memcmp(&resp.next_block_id, &EXPECTED_NEXT_BLOCK_ID, 16));

    /* clean up. */
    dispose((disposable_t*)&buffer);
    dispose((disposable_t*)&resp);
    dispose((disposable_t*)&alloc_opts);
}
