/**
 * \file test/ssock/test_ssock_write_string.cpp
 *
 * Unit tests for ssock_write_string.
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
 * Test that ssock_write_string does runtime parameter checks.
 */
TEST(test_ssock_write_string, parameter_checks)
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

    const char* EXPECTED_STRING = "Test string.";

    /* call with invalid socket. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_write_string(nullptr, EXPECTED_STRING));

    /* call with invalid val pointer. */
    EXPECT_EQ(VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_write_string(&sock, nullptr));

    /* clean up */
    dispose((disposable_t*)&sock);
}

/**
 * Test that ssock_write_string writes a string packet as expected.
 */
TEST(test_ssock_write_string, happy_path)
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

    const char* EXPECTED_STRING = "Test string.";

    /* writing a data packet should succeed. */
    EXPECT_EQ(VCBLOCKCHAIN_STATUS_SUCCESS,
        ssock_write_string(&sock, EXPECTED_STRING));

    /* the internal write method should have been called three times. */
    ASSERT_EQ(3U, write_calls.size());

    /* the socket is the first argument. */
    EXPECT_EQ(&sock, write_calls[0]->sock);

    /* the first buffer contains the data type. */
    ASSERT_EQ(sizeof(uint8_t), write_calls[0]->buf.size());
    EXPECT_EQ(SSOCK_DATA_TYPE_STRING, write_calls[0]->buf[0]);

    /* the second buffer contains the size. */
    ASSERT_EQ(sizeof(uint32_t), write_calls[1]->buf.size());
    uint32_t net_size;
    memcpy(&net_size, &write_calls[1]->buf[0], sizeof(net_size));
    EXPECT_EQ(strlen(EXPECTED_STRING), (size_t)vcntohl(net_size));

    /* the third buffer contains the data. */
    ASSERT_EQ(strlen(EXPECTED_STRING), write_calls[2]->buf.size());
    EXPECT_EQ(0,
        memcmp(
            EXPECTED_STRING, &write_calls[2]->buf[0], strlen(EXPECTED_STRING)));

    /* clean up */
    dispose((disposable_t*)&sock);
}
