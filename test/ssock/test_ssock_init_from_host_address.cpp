/**
 * \file test/ssock/test_ssock_init_from_host_address.cpp
 *
 * Unit tests for ssock_init_from_host_address.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <gtest/gtest.h>
#include <vcblockchain/ssock.h>

using namespace std;

/**
 * Test that ssock_init_from_host_address returns an error if sock is NULL.
 */
TEST(test_ssock_init_from_host_address, null_sock)
{
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_init_from_host_address(NULL, "example.com", 80));
}

/**
 * Test that ssock_init_from_host_address returns an error if hostaddr is NULL.
 */
TEST(test_ssock_init_from_host_address, null_hostaddr)
{
    ssock sock;

    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_init_from_host_address(&sock, NULL, 80));
}

/**
 * Test that ssock_init_from_host_address returns an error if port > 65535.
 */
TEST(test_ssock_init_from_host_address, invalid_port)
{
    ssock sock;

    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ARG,
        ssock_init_from_host_address(&sock, "example.com", 1000000));
}

/**
 * Test that ssock_init_from_host_address returns an error if the address can't
 * be resolved.
 */
TEST(test_ssock_init_from_host_address, unresolvable_address)
{
    ssock sock;

    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_INVALID_ADDRESS,
        ssock_init_from_host_address(&sock, "example.invalid", 80));
}

/**
 * Test that ssock_init_from_host_address returns an error if it can't connect.
 */
TEST(test_ssock_init_from_host_address, connection_refused)
{
    ssock sock;

    /* port 0 is an invalid port for client connections. */
    EXPECT_EQ(
        VCBLOCKCHAIN_ERROR_CONNECTION_REFUSED,
        ssock_init_from_host_address(&sock, "127.0.0.1", 0));
}

/**
 * Test that ssock_init_from_host_address works for a valid address and port.
 */
TEST(test_ssock_init_from_host_address, happy_path)
{
    ssock sock;

    /* port 0 is an invalid port for client connections. */
    ASSERT_EQ(
        VCBLOCKCHAIN_STATUS_SUCCESS,
        ssock_init_from_host_address(&sock, "127.0.0.1", 22));

    dispose((disposable_t*)&sock);
}
