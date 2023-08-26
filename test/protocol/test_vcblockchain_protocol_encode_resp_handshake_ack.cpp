/**
 * \file test/protocol/test_vcblockchain_protocol_encode_resp_handshake_ack.cpp
 *
 * Unit tests for encoding the response portion of the handshake ack.
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

TEST_SUITE(test_vcblockchain_protocol_encode_resp_handshake_ack);

/**
 * Test the basics of the encoding.
 */
TEST(basics)
{
    allocator_options_t alloc_opts;
    vccrypt_buffer_t out;
    const uint32_t EXPECTED_OFFSET = 71;
    const uint32_t EXPECTED_STATUS = 14;

    /* create an allocator instance. */
    malloc_allocator_options_init(&alloc_opts);

    /* PRECONDITION: output should have a null data and 0 size. */
    out.data = nullptr;
    out.size = 0U;

    /* encoding the handshake ack should succeed. */
    TEST_ASSERT(
        VCCRYPT_STATUS_SUCCESS
            == vcblockchain_protocol_encode_resp_handshake_ack(
                    &out, &alloc_opts, EXPECTED_OFFSET, EXPECTED_STATUS));

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
    TEST_EXPECT(PROTOCOL_REQ_ID_HANDSHAKE_ACKNOWLEDGE == ntohl(net_request));
    buf += sizeof(net_request); size -= sizeof(net_request);

    /* then comes the status. */
    uint32_t net_status;
    TEST_ASSERT(size >= sizeof(net_status));
    memcpy(&net_status, buf, sizeof(net_status));
    TEST_EXPECT(EXPECTED_STATUS == ntohl(net_status));
    buf += sizeof(net_status); size -= sizeof(net_status);

    /* then comes the offset. */
    uint32_t net_offset;
    TEST_ASSERT(size == sizeof(net_offset));
    memcpy(&net_offset, buf, sizeof(net_offset));
    TEST_EXPECT(EXPECTED_OFFSET == ntohl(net_offset));

    /* clean up. */
    dispose((disposable_t*)&out);
    dispose((disposable_t*)&alloc_opts);
}
