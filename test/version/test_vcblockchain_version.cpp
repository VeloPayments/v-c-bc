/**
 * \file test/version/test_vcblockchain_version.cpp
 *
 * Unit tests for vcblockchain_version.
 *
 * \copyright 2021-2023 Velo Payments, Inc.  All rights reserved.
 */

#include <config.h>
#include <cstring>
#include <minunit/minunit.h>
#include <vcblockchain/version.h>

using namespace std;

TEST_SUITE(vcblockchain_version_test);

TEST(verify_version_information_set)
{
    const char* version = vcblockchain_version();

    TEST_ASSERT(nullptr != version);
    TEST_EXPECT(!strcmp(VCBLOCKCHAIN_VERSION, version));
}
