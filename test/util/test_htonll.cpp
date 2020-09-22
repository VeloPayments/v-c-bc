/**
 * \file
 * test/util/test_htonll.cpp
 *
 * Unit tests for htonll.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vcblockchain/byteswap.h>

using namespace std;

/**
 * Test the happy path for htonll.
 */
TEST(test_htonll, htonll)
{
    EXPECT_EQ(0x0000000000000001LL, htonll(0x0100000000000000LL));
    EXPECT_EQ(0x0000000000000100LL, htonll(0x0001000000000000LL));
    EXPECT_EQ(0x0000000000010000LL, htonll(0x0000010000000000LL));
    EXPECT_EQ(0x0000000001000000LL, htonll(0x0000000100000000LL));
    EXPECT_EQ(0x0000000100000000LL, htonll(0x0000000001000000LL));
    EXPECT_EQ(0x0000010000000000LL, htonll(0x0000000000010000LL));
    EXPECT_EQ(0x0001000000000000LL, htonll(0x0000000000000100LL));
    EXPECT_EQ(0x0100000000000000LL, htonll(0x0000000000000001LL));
}

/**
 * Test the happy path for ntohll.
 */
TEST(test_htonll, ntohll)
{
    EXPECT_EQ(0x0000000000000001LL, ntohll(0x0100000000000000LL));
    EXPECT_EQ(0x0000000000000100LL, ntohll(0x0001000000000000LL));
    EXPECT_EQ(0x0000000000010000LL, ntohll(0x0000010000000000LL));
    EXPECT_EQ(0x0000000001000000LL, ntohll(0x0000000100000000LL));
    EXPECT_EQ(0x0000000100000000LL, ntohll(0x0000000001000000LL));
    EXPECT_EQ(0x0000010000000000LL, ntohll(0x0000000000010000LL));
    EXPECT_EQ(0x0001000000000000LL, ntohll(0x0000000000000100LL));
    EXPECT_EQ(0x0100000000000000LL, ntohll(0x0000000000000001LL));
}
