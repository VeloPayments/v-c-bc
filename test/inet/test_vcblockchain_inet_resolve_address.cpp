/**
 * \file
 * test/protocol/test_vcblockchain_inet_resolve_address.cpp
 *
 * Unit tests for vcblockchain_inet_resolve_address.
 *
 * \copyright 2023 Velo Payments, Inc.  All rights reserved.
 */

#include <minunit/minunit.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/inet.h>

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_resource;

TEST_SUITE(test_vcblockchain_inet_resolve_address);

/**
 * This method should perform null checks on its pointer parameters.
 */
TEST(parameters)
{
    char* canonical_addr;
    rcpr_allocator* alloc;
    const char* EXPECTED_QUERY_ADDR = "localhost";
    const int EXPECTED_DOMAIN = AF_INET;

    /* create an allocator instance. */
    TEST_ASSERT(STATUS_SUCCESS == rcpr_malloc_allocator_create(&alloc));

    /* this method performs null checks on pointer parameters. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_inet_resolve_address(
                    nullptr, alloc, EXPECTED_QUERY_ADDR, EXPECTED_DOMAIN));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_inet_resolve_address(
                    &canonical_addr, nullptr, EXPECTED_QUERY_ADDR,
                    EXPECTED_DOMAIN));
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_inet_resolve_address(
                    &canonical_addr, alloc, nullptr, EXPECTED_DOMAIN));

    /* clean up. */
    TEST_ASSERT(
        STATUS_SUCCESS
            == resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Domain must be AF_INET or AF_INET6.
 */
TEST(domain_check)
{
    char* canonical_addr;
    rcpr_allocator* alloc;
    const char* EXPECTED_QUERY_ADDR = "localhost";

    /* create an allocator instance. */
    TEST_ASSERT(STATUS_SUCCESS == rcpr_malloc_allocator_create(&alloc));

    /* Any parameter other than AF_INET or AF_INET6 results in an error. */
    TEST_EXPECT(
        VCBLOCKCHAIN_ERROR_INVALID_ARG
            == vcblockchain_inet_resolve_address(
                    &canonical_addr, alloc, EXPECTED_QUERY_ADDR, AF_UNIX));

    /* clean up. */
    TEST_ASSERT(
        STATUS_SUCCESS
            == resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * We can resolve localhost as an IPv4 domain.
 */
TEST(localhost_IPv4)
{
    char* canonical_addr;
    rcpr_allocator* alloc;
    const char* EXPECTED_QUERY_ADDR = "localhost";

    /* create an allocator instance. */
    TEST_ASSERT(STATUS_SUCCESS == rcpr_malloc_allocator_create(&alloc));

    /* Resolving the domain should succeed. */
    TEST_ASSERT(
        STATUS_SUCCESS
            == vcblockchain_inet_resolve_address(
                    &canonical_addr, alloc, EXPECTED_QUERY_ADDR, AF_INET));

    /* the resolved address should be 127.0.0.1. */
    TEST_EXPECT(!strcmp("127.0.0.1", canonical_addr));

    /* clean up. */
    TEST_ASSERT(
        STATUS_SUCCESS == rcpr_allocator_reclaim(alloc, canonical_addr));
    TEST_ASSERT(
        STATUS_SUCCESS
            == resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * We can resolve localhost as an IPv6 domain.
 */
TEST(localhost_IPv6)
{
    char* canonical_addr;
    rcpr_allocator* alloc;
    const char* EXPECTED_QUERY_ADDR = "localhost";

    /* create an allocator instance. */
    TEST_ASSERT(STATUS_SUCCESS == rcpr_malloc_allocator_create(&alloc));

    /* Resolving the domain should succeed. */
    TEST_ASSERT(
        STATUS_SUCCESS
            == vcblockchain_inet_resolve_address(
                    &canonical_addr, alloc, EXPECTED_QUERY_ADDR, AF_INET6));

    /* the resolved address should be ::1. */
    TEST_EXPECT(!strcmp("::1", canonical_addr));

    /* clean up. */
    TEST_ASSERT(
        STATUS_SUCCESS == rcpr_allocator_reclaim(alloc, canonical_addr));
    TEST_ASSERT(
        STATUS_SUCCESS
            == resource_release(rcpr_allocator_resource_handle(alloc)));
}
