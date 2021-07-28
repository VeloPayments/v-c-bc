/**
 * \file test/ssock/test_ssock_read_string.cpp
 *
 * Unit tests for ssock_read_string.
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
 */

#include <algorithm>
#include <gtest/gtest.h>
#include <list>
#include <memory>
#include <vcblockchain/byteswap.h>
#include <vpr/allocator/malloc_allocator.h>

#include "dummy_ssock.h"

using namespace std;

/**
 * Test that ssock_read_sttring does runtime parameter checks.
 */
TEST(test_ssock_read_string, parameter_checks)
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

    char* val = nullptr;

    /* call with invalid socket. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_string(nullptr, &alloc_opts, &val));

    /* call with invalid alloc_opts. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_string(&sock, nullptr, &val));

    /* call with invalid value string pointer. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_read_string(&sock, &alloc_opts, nullptr));

    /* clean up */
    dispose((disposable_t*)&sock);
    dispose((disposable_t*)&alloc_opts);
}

/**
 * Test that ssock_read_string reads a string packet as expected.
 */
TEST(test_ssock_read_string, happy_path)
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

    const char* EXPECTED_STRING = "This is a test.";

    /* create a buffer for the type. */
    auto b1 = make_shared<vector<uint8_t>>();
    b1->push_back(0);
    b1->push_back(0);
    b1->push_back(0);
    b1->push_back((uint8_t)(SSOCK_DATA_TYPE_STRING & 0x000000FF));
    io_buf.push_back(b1);

    /* create a buffer for the size. */
    auto b2 = make_shared<vector<uint8_t>>();
    uint32_t size = strlen(EXPECTED_STRING);
    uint32_t net_size = vchtonl(size);
    uint8_t size_buf[4];
    memcpy(size_buf, &net_size, 4);
    copy(size_buf, size_buf + 4, back_inserter(*b2));
    io_buf.push_back(b2);

    /* create a buffer for the string value. */
    auto b3 = make_shared<vector<uint8_t>>();
    copy(EXPECTED_STRING, EXPECTED_STRING + size, back_inserter(*b3));
    io_buf.push_back(b3);

    char* val = nullptr;

    /* reading a data packet should succeed. */
    ASSERT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        ssock_read_string(&sock, &alloc_opts, &val));

    /* the value should not be null. */
    ASSERT_NE(nullptr, val);
    /* the length of the string should be the same as our expected string. */
    ASSERT_EQ(strlen(EXPECTED_STRING), strlen(val));

    /* the two strings should be equal. */
    EXPECT_EQ(0, strcmp(EXPECTED_STRING, val));

    /* clean up */
    dispose((disposable_t*)&sock);
    release(&alloc_opts, val);
    dispose((disposable_t*)&alloc_opts);
}
