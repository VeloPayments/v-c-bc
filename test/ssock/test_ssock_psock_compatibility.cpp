/**
 * \file test/ssock/test_ssock_psock_compatibility.cpp
 *
 * Unit tests to verify that ssock and psock are compatible.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <memory>
#include <rcpr/psock.h>
#include <rcpr/socket_utilities.h>
#include <vcblockchain/byteswap.h>
#include <vpr/allocator/malloc_allocator.h>

#include "dummy_ssock.h"

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_psock;
RCPR_IMPORT_resource;
RCPR_IMPORT_socket_utilities;

using namespace std;

/**
 * Test that ssock_write_data can be read by psock_read_boxed_data.
 */
TEST(test_ssock_psock_compatibility, ssock_write_data)
{
    const char* EXPECTED_VAL = "This is a test.";
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    char* buf;
    size_t buf_len;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from lhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, lhs));

    /* create the psock from rhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, rhs));

    /* write the data value. */
    ASSERT_EQ(0, ssock_write_data(&ss, EXPECTED_VAL, strlen(EXPECTED_VAL)));

    /* read the data value. */
    ASSERT_EQ(0, psock_read_boxed_data(ps, alloc, (void**)&buf, &buf_len));

    /* the sizes should match. */
    EXPECT_EQ(strlen(EXPECTED_VAL), buf_len);

    /* the two values should match. */
    EXPECT_EQ(0, memcmp(buf, EXPECTED_VAL, buf_len));

    /* clean up. */
    ASSERT_EQ(0, rcpr_allocator_reclaim(alloc, buf));
    dispose((disposable_t*)&ss);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_write_string can be read by psock_read_boxed_data.
 */
TEST(test_ssock_psock_compatibility, ssock_write_string)
{
    const char* EXPECTED_VAL = "This is a test.";
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    char* buf;
    size_t buf_len;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from lhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, lhs));

    /* create the psock from rhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, rhs));

    /* write the string value. */
    ASSERT_EQ(0, ssock_write_string(&ss, EXPECTED_VAL));

    /* read the string value. */
    ASSERT_EQ(0, psock_read_boxed_string(ps, alloc, &buf, &buf_len));

    /* the sizes should match. */
    EXPECT_EQ(strlen(EXPECTED_VAL), buf_len);

    /* the two values should match. */
    EXPECT_STREQ(buf, EXPECTED_VAL);

    /* clean up. */
    ASSERT_EQ(0, rcpr_allocator_reclaim(alloc, buf));
    dispose((disposable_t*)&ss);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_write_uint64 can be read by psock_read_boxed_uint64.
 */
TEST(test_ssock_psock_compatibility, ssock_write_uint64)
{
    uint64_t EXPECTED_VAL = 38282893;
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    uint64_t val;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from lhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, lhs));

    /* create the psock from rhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, rhs));

    /* write the integer value. */
    ASSERT_EQ(0, ssock_write_uint64(&ss, EXPECTED_VAL));

    /* read the integer value. */
    ASSERT_EQ(0, psock_read_boxed_uint64(ps, &val));

    /* the two values should match. */
    EXPECT_EQ(EXPECTED_VAL, val);

    /* clean up. */
    dispose((disposable_t*)&ss);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_write_int64 can be read by psock_read_boxed_int64.
 */
TEST(test_ssock_psock_compatibility, ssock_write_int64)
{
    int64_t EXPECTED_VAL = 38282893;
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    int64_t val;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from lhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, lhs));

    /* create the psock from rhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, rhs));

    /* write the integer value. */
    ASSERT_EQ(0, ssock_write_int64(&ss, EXPECTED_VAL));

    /* read the integer value. */
    ASSERT_EQ(0, psock_read_boxed_int64(ps, &val));

    /* the two values should match. */
    EXPECT_EQ(EXPECTED_VAL, val);

    /* clean up. */
    dispose((disposable_t*)&ss);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_write_uint8 can be read by psock_read_boxed_uint8.
 */
TEST(test_ssock_psock_compatibility, ssock_write_uint8)
{
    uint8_t EXPECTED_VAL = 38;
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    uint8_t val;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from lhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, lhs));

    /* create the psock from rhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, rhs));

    /* write the integer value. */
    ASSERT_EQ(0, ssock_write_uint8(&ss, EXPECTED_VAL));

    /* read the integer value. */
    ASSERT_EQ(0, psock_read_boxed_uint8(ps, &val));

    /* the two values should match. */
    EXPECT_EQ(EXPECTED_VAL, val);

    /* clean up. */
    dispose((disposable_t*)&ss);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_write_int8 can be read by psock_read_boxed_int8.
 */
TEST(test_ssock_psock_compatibility, ssock_write_int8)
{
    int8_t EXPECTED_VAL = 38;
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    int8_t val;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from lhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, lhs));

    /* create the psock from rhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, rhs));

    /* write the integer value. */
    ASSERT_EQ(0, ssock_write_int8(&ss, EXPECTED_VAL));

    /* read the integer value. */
    ASSERT_EQ(0, psock_read_boxed_int8(ps, &val));

    /* the two values should match. */
    EXPECT_EQ(EXPECTED_VAL, val);

    /* clean up. */
    dispose((disposable_t*)&ss);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_read_data can read from psock_write_boxed_data.
 */
TEST(test_ssock_psock_compatibility, ssock_read_data)
{
    const char* EXPECTED_VAL = "This is a test.";
    allocator_options_t alloc_opts;
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    char* buf;
    uint32_t buf_len;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a VPR allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from rhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, rhs));

    /* create the psock from lhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, lhs));

    /* write the data value. */
    ASSERT_EQ(0,
        psock_write_boxed_data(ps, EXPECTED_VAL, strlen(EXPECTED_VAL)));

    /* read the data value. */
    ASSERT_EQ(0, ssock_read_data(&ss, &alloc_opts, (void**)&buf, &buf_len));

    /* the sizes should match. */
    EXPECT_EQ(strlen(EXPECTED_VAL), buf_len);

    /* the two values should match. */
    EXPECT_EQ(0, memcmp(buf, EXPECTED_VAL, buf_len));

    /* clean up. */
    release(&alloc_opts, buf);
    dispose((disposable_t*)&ss);
    dispose((disposable_t*)&alloc_opts);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_read_string can read from psock_write_boxed_string.
 */
TEST(test_ssock_psock_compatibility, ssock_read_string)
{
    const char* EXPECTED_VAL = "This is a test.";
    allocator_options_t alloc_opts;
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    char* buf;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a VPR allocator. */
    malloc_allocator_options_init(&alloc_opts);

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from rhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, rhs));

    /* create the psock from lhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, lhs));

    /* write the string value. */
    ASSERT_EQ(0,
        psock_write_boxed_string(ps, EXPECTED_VAL));

    /* read the string value. */
    ASSERT_EQ(0, ssock_read_string(&ss, &alloc_opts, &buf));

    /* the two values should match. */
    EXPECT_STREQ(EXPECTED_VAL, buf);

    /* clean up. */
    release(&alloc_opts, buf);
    dispose((disposable_t*)&ss);
    dispose((disposable_t*)&alloc_opts);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_read_uint64 can read from psock_write_boxed_uint64.
 */
TEST(test_ssock_psock_compatibility, ssock_read_uint64)
{
    uint64_t EXPECTED_VAL = 22838384;
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    uint64_t val;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from rhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, rhs));

    /* create the psock from lhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, lhs));

    /* write the integer value. */
    ASSERT_EQ(0,
        psock_write_boxed_uint64(ps, EXPECTED_VAL));

    /* read the integer value. */
    ASSERT_EQ(0, ssock_read_uint64(&ss, &val));

    /* the two values should match. */
    EXPECT_EQ(EXPECTED_VAL, val);

    /* clean up. */
    dispose((disposable_t*)&ss);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_read_int64 can read from psock_write_boxed_int64.
 */
TEST(test_ssock_psock_compatibility, ssock_read_int64)
{
    int64_t EXPECTED_VAL = 22838384;
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    int64_t val;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from rhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, rhs));

    /* create the psock from lhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, lhs));

    /* write the integer value. */
    ASSERT_EQ(0,
        psock_write_boxed_int64(ps, EXPECTED_VAL));

    /* read the integer value. */
    ASSERT_EQ(0, ssock_read_int64(&ss, &val));

    /* the two values should match. */
    EXPECT_EQ(EXPECTED_VAL, val);

    /* clean up. */
    dispose((disposable_t*)&ss);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_read_uint8 can read from psock_write_boxed_uint8.
 */
TEST(test_ssock_psock_compatibility, ssock_read_uint8)
{
    uint8_t EXPECTED_VAL = 22;
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    uint8_t val;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from rhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, rhs));

    /* create the psock from lhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, lhs));

    /* write the integer value. */
    ASSERT_EQ(0,
        psock_write_boxed_uint8(ps, EXPECTED_VAL));

    /* read the integer value. */
    ASSERT_EQ(0, ssock_read_uint8(&ss, &val));

    /* the two values should match. */
    EXPECT_EQ(EXPECTED_VAL, val);

    /* clean up. */
    dispose((disposable_t*)&ss);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}

/**
 * Test that ssock_read_int8 can read from psock_write_boxed_int8.
 */
TEST(test_ssock_psock_compatibility, ssock_read_int8)
{
    int8_t EXPECTED_VAL = 22;
    rcpr_allocator* alloc;
    ssock ss;
    psock* ps;
    int lhs, rhs;
    int8_t val;

    /* create an RCPR allocator. */
    ASSERT_EQ(0, rcpr_malloc_allocator_create(&alloc));

    /* create a socket pair for testing. */
    ASSERT_EQ(0,
        socket_utility_socketpair(AF_UNIX, SOCK_STREAM, 0, &lhs, &rhs));

    /* init the ssock from rhs. */
    ASSERT_EQ(0, ssock_init_from_posix(&ss, rhs));

    /* create the psock from lhs. */
    ASSERT_EQ(0, psock_create_from_descriptor(&ps, alloc, lhs));

    /* write the integer value. */
    ASSERT_EQ(0,
        psock_write_boxed_int8(ps, EXPECTED_VAL));

    /* read the integer value. */
    ASSERT_EQ(0, ssock_read_int8(&ss, &val));

    /* the two values should match. */
    EXPECT_EQ(EXPECTED_VAL, val);

    /* clean up. */
    dispose((disposable_t*)&ss);
    ASSERT_EQ(0, resource_release(psock_resource_handle(ps)));
    ASSERT_EQ(0, resource_release(rcpr_allocator_resource_handle(alloc)));
}
