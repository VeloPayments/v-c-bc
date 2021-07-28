/**
 * \file test/ssock/test_ssock_read_uint64.cpp
 *
 * Unit tests for ssock_read_uint64.
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
 */

#include <algorithm>
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <list>
#include <memory>
#include <vcblockchain/byteswap.h>
#include <vpr/allocator/malloc_allocator.h>

#include "dummy_ssock.h"

using namespace std;

/**
 * Test that ssock_read_uint64 does runtime parameter checks.
 */
TEST(test_ssock_read_uint64, parameter_checks)
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

    uint64_t val = 0U;

    /* call with invalid socket. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_uint64(nullptr, &val));

    /* call with invalid value pointer. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_uint64(&sock, nullptr));

    /* clean up */
    dispose((disposable_t*)&sock);
}

/**
 * Test that ssock_read_uint64 writes a value packet as expected.
 */
TEST(test_ssock_read_uint64, happy_path)
{
    ssock sock;
    list<shared_ptr<vector<uint8_t>>> io_buf;

    /* build a simple dummy socket. */
    ASSERT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        dummy_ssock_init(
            &sock,
            [&](ssock*, void* b, size_t* sz) -> int {
                shared_ptr<vector<uint8_t>> buf = io_buf.front();
                io_buf.pop_front();

                if (*sz != buf->size())
                    return VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_SIZE;

                copy(buf->begin(), buf->end(), (uint8_t*)b);

                return VCBLOCKCHAIN_STATUS_SUCCESS;
            },
            [&](ssock*, const void*, size_t*) -> int {
                return VCBLOCKCHAIN_STATUS_SUCCESS;
            }));

    uint64_t EXPECTED_VAL = 10;

    /* create a buffer for the type. */
    auto b1 = make_shared<vector<uint8_t>>();
    b1->push_back(0);
    b1->push_back(0);
    b1->push_back(0);
    b1->push_back((uint8_t)(SSOCK_DATA_TYPE_UINT64 & 0x000000FF));
    io_buf.push_back(b1);

    /* create a buffer for the size. */
    auto b2 = make_shared<vector<uint8_t>>();
    b2->push_back(0);
    b2->push_back(0);
    b2->push_back(0);
    b2->push_back(8);
    io_buf.push_back(b2);

    /* create a buffer for the uint64 value. */
    auto b3 = make_shared<vector<uint8_t>>();
    uint64_t nval = htonll(EXPECTED_VAL);
    uint8_t buf[8];
    memcpy(buf, &nval, 8);
    copy(buf, buf + 8, back_inserter(*b3));
    io_buf.push_back(b3);

    uint64_t val = 0U;

    /* reading a data packet should succeed. */
    ASSERT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        ssock_read_uint64(&sock, &val));

    /* the uint64_t value should be equal to our expected value. */
    EXPECT_EQ(EXPECTED_VAL, val);

    /* clean up */
    dispose((disposable_t*)&sock);
}
