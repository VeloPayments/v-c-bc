/**
 * \file test/version/test_vcblockchain_version.cpp
 *
 * Unit tests for vcblockchain_version.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <config.h>
#include <vcblockchain/version.h>

/* DISABLED GTEST */
#if 0

using namespace std;

TEST(vcblockchain_version_test, verify_version_information_set)
{
    const char* version = vcblockchain_version();

    ASSERT_NE(nullptr, version);
    EXPECT_STREQ(VCBLOCKCHAIN_VERSION, version);
}
#endif
