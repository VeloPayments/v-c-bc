/**
 * \file test/ssock/test_ssock_read_data.cpp
 *
 * Unit tests for ssock_read_data.
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
 */

#include <algorithm>
#include <gtest/gtest.h>
#include <list>
#include <memory>
#include <vpr/allocator/malloc_allocator.h>

#include "dummy_ssock.h"

using namespace std;

/**
 * Test that ssock_read_data does runtime parameter checks.
 */
TEST(test_ssock_read_data, parameter_checks)
{
    ssock sock;
    allocator_options_t alloc_opts;

    /* create malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

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

    void* val = nullptr;
    uint32_t size = 0U;

    /* call with invalid socket. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_data(nullptr, &alloc_opts, &val, &size));

    /* call with invalid alloc_opts. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_data(&sock, nullptr, &val, &size));

    /* call with invalid value buffer pointer. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_data(&sock, &alloc_opts, nullptr, &size));

    /* call with invalid size pointer. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_data(&sock, &alloc_opts, &val, nullptr));

    /* clean up */
    dispose((disposable_t*)&sock);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * Test that ssock_read_data writes a data packet as expected.
 */
TEST(test_ssock_read_data, happy_path)
{
    ssock sock;
    list<shared_ptr<vector<uint8_t>>> io_buf;
    allocator_options_t alloc_opts;

    /* create malloc allocator. */
    malloc_allocator_options_init(&alloc_opts);

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

    int32_t EXPECTED_VAL = 10;

    /* create a buffer for the type. */
    auto b1 = make_shared<vector<uint8_t>>();
    b1->push_back(0);
    b1->push_back(0);
    b1->push_back(0);
    b1->push_back((uint8_t)(SSOCK_DATA_TYPE_DATA_PACKET & 0x000000FF));
    io_buf.push_back(b1);

    /* create a buffer for the size. */
    auto b2 = make_shared<vector<uint8_t>>();
    b2->push_back(0);
    b2->push_back(0);
    b2->push_back(0);
    b2->push_back(4);
    io_buf.push_back(b2);

    /* create a buffer for the int value. */
    auto b3 = make_shared<vector<uint8_t>>();
    b3->push_back(10);
    b3->push_back(0);
    b3->push_back(0);
    b3->push_back(0);
    io_buf.push_back(b3);

    void* val = nullptr;
    uint32_t size;

    /* reading a data packet should succeed. */
    ASSERT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        ssock_read_data(&sock, &alloc_opts, &val, &size));

    /* the size of the data packet should be the same as our expected val. */
    ASSERT_EQ(sizeof(EXPECTED_VAL), size);
    /* the value should not be null. */
    ASSERT_NE(nullptr, val);

    /* the int32_t value should be equal to our expected value. */
    EXPECT_EQ(EXPECTED_VAL, *((int32_t*)val));

    /* clean up */
    dispose((disposable_t*)&sock);
    release(&alloc_opts, val);
    dispose((disposable_t*)&alloc_opts);
}
