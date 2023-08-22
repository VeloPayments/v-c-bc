/**
 * \file
 * test/protocol/test_vcblockchain_inet_resolve_address.cpp
 *
 * Unit tests for vcblockchain_inet_resolve_address.
 *
 * \copyright 2023 Velo Payments, Inc.  All rights reserved.
 */

#include <vcblockchain/error_codes.h>
#include <vcblockchain/inet.h>

/* DISABLED GTEST */
#if 0

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_resource;

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(test_vcblockchain_inet_resolve_address, parameters)
{
    char* canonical_addr;
    rcpr_allocator* alloc;
    const char* EXPECTED_QUERY_ADDR = "localhost";
    const int EXPECTED_DOMAIN = AF_INET;

    /* create an allocator instance. */
    ASSERT_EQ(STATUS_SUCCESS, rcpr_malloc_allocator_create(&alloc));

    /* this method performs null checks on pointer parameters. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_inet_resolve_address(
            nullptr, alloc, EXPECTED_QUERY_ADDR, EXPECTED_DOMAIN));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_inet_resolve_address(
            &canonical_addr, nullptr, EXPECTED_QUERY_ADDR, EXPECTED_DOMAIN));
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_inet_resolve_address(
            &canonical_addr, alloc, nullptr, EXPECTED_DOMAIN));

    /* clean up. */
    ASSERT_EQ(
        STATUS_SUCCESS,
        resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Domain must be AF_INET or AF_INET6.
 */
TEST(test_vcblockchain_inet_resolve_address, domain_check)
{
    char* canonical_addr;
    rcpr_allocator* alloc;
    const char* EXPECTED_QUERY_ADDR = "localhost";

    /* create an allocator instance. */
    ASSERT_EQ(STATUS_SUCCESS, rcpr_malloc_allocator_create(&alloc));

    /* Any parameter other than AF_INET or AF_INET6 results in an error. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        vcblockchain_inet_resolve_address(
            &canonical_addr, alloc, EXPECTED_QUERY_ADDR, AF_UNIX));

    /* clean up. */
    ASSERT_EQ(
        STATUS_SUCCESS,
        resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * We can resolve localhost as an IPv4 domain.
 */
TEST(test_vcblockchain_inet_resolve_address, localhost_IPv4)
{
    char* canonical_addr;
    rcpr_allocator* alloc;
    const char* EXPECTED_QUERY_ADDR = "localhost";

    /* create an allocator instance. */
    ASSERT_EQ(STATUS_SUCCESS, rcpr_malloc_allocator_create(&alloc));

    /* Resolving the domain should succeed. */
    ASSERT_EQ(
        STATUS_SUCCESS,
        vcblockchain_inet_resolve_address(
            &canonical_addr, alloc, EXPECTED_QUERY_ADDR, AF_INET));

    /* the resolved address should be 127.0.0.1. */
    EXPECT_STREQ("127.0.0.1", canonical_addr);

    /* clean up. */
    ASSERT_EQ(STATUS_SUCCESS, rcpr_allocator_reclaim(alloc, canonical_addr));
    ASSERT_EQ(
        STATUS_SUCCESS,
        resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * We can resolve localhost as an IPv6 domain.
 */
TEST(test_vcblockchain_inet_resolve_address, localhost_IPv6)
{
    char* canonical_addr;
    rcpr_allocator* alloc;
    const char* EXPECTED_QUERY_ADDR = "localhost";

    /* create an allocator instance. */
    ASSERT_EQ(STATUS_SUCCESS, rcpr_malloc_allocator_create(&alloc));

    /* Resolving the domain should succeed. */
    ASSERT_EQ(
        STATUS_SUCCESS,
        vcblockchain_inet_resolve_address(
            &canonical_addr, alloc, EXPECTED_QUERY_ADDR, AF_INET6));

    /* the resolved address should be ::1. */
    EXPECT_STREQ("::1", canonical_addr);

    /* clean up. */
    ASSERT_EQ(STATUS_SUCCESS, rcpr_allocator_reclaim(alloc, canonical_addr));
    ASSERT_EQ(
        STATUS_SUCCESS,
        resource_release(rcpr_allocator_resource_handle(alloc)));
}
#endif
