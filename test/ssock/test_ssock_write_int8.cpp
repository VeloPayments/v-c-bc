/**
 * \file test/ssock/test_ssock_write_int8.cpp
 *
 * Unit tests for ssock_write_int8.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <memory>
#include <vcblockchain/byteswap.h>
#include <vpr/allocator/malloc_allocator.h>

#include "dummy_ssock.h"

using namespace std;

/**
 * Test that ssock_write_int8 does runtime parameter checks.
 */
TEST(test_ssock_write_int8, parameter_checks)
{
    ssock sock;

    /* build a simple dummy socket. */
    ASSERT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_ssock_init(
            &sock,
            [&](ssock*, void*, size_t*) -> int {
                return VCBLOCKCHAIN_STATUS_SUCCESS;
            },
            [&](ssock*, const void*, size_t*) -> int {
                return VCBLOCKCHAIN_STATUS_SUCCESS;
            }));

    int8_t val = 10;

    /* call with invalid socket. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG, ssock_write_int8(nullptr, val));

    /* clean up */
    dispose((disposable_t*)&sock);
}

/**
 * Test that ssock_write_int8 writes a value packet as expected.
 */
TEST(test_ssock_write_int8, happy_path)
{
    ssock sock;
    vector<shared_ptr<ssock_write_params>> write_calls;

    /* build a simple dummy socket. */
    ASSERT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_ssock_init(
            &sock,
            [&](ssock*, void*, size_t*) -> int {
                return VCBLOCKCHAIN_STATUS_SUCCESS;
            },
            [&](ssock* sock, const void* val, size_t* size) -> int {
                write_calls.push_back(
                    make_shared<ssock_write_params>(
                        sock, val, *size));

                return VCBLOCKCHAIN_STATUS_SUCCESS;
            }));

    int8_t val = 10;

    /* writing a data packet should succeed. */
    EXPECT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS, ssock_write_int8(&sock, val));

    /* the internal write method should have been called three times. */
    ASSERT_EQ(3U, write_calls.size());

    /* the socket is the first argument. */
    EXPECT_EQ(&sock, write_calls[0]->sock);

    /* the first buffer contains the data type. */
    ASSERT_EQ(sizeof(uint8_t), write_calls[0]->buf.size());
    EXPECT_EQ(SSOCK_DATA_TYPE_UINT8, write_calls[0]->buf[0]);

    /* the second buffer contains the size. */
    ASSERT_EQ(sizeof(uint32_t), write_calls[1]->buf.size());
    uint32_t net_size;
    memcpy(&net_size, &write_calls[1]->buf[0], sizeof(net_size));
    EXPECT_EQ(sizeof(val), (size_t)vcntohl(net_size));

    /* the third buffer contains the data. */
    ASSERT_EQ(sizeof(val), write_calls[2]->buf.size());
    int8_t v2;
    memcpy(&v2, &write_calls[2]->buf[0], sizeof(v2));
    EXPECT_EQ(val, v2);

    /* clean up */
    dispose((disposable_t*)&sock);
}
