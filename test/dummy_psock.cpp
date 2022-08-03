/**
 * \file test/dummy_psock.cpp
 *
 * Dummy psock implementation, used for testing.
 *
 * \copyright 2022 Velo Payments, Inc.  All rights reserved.
 */

#include <algorithm>

#include "dummy_psock.h"

using namespace std;

RCPR_IMPORT_allocator_as(rcpr);
RCPR_IMPORT_psock;
RCPR_IMPORT_resource;

/**
 * \brief Constructor for \ref psock_write_params.
 */
psock_write_params::psock_write_params(psock* s, const void* b, size_t sz)
    : sock(s)
{
    const uint8_t* in = (const uint8_t*)b;

    buf.reserve(sz);
    copy(in, in + sz, back_inserter(buf));
}

/**
 * \brief Dummy psock context.
 */
struct dummy_psock
{
    dummy_psock(
        function<int(psock*, void*, size_t*)> _readfunc,
        function<int(psock*, const void*, size_t*)> _writefunc)
        : readfunc(_readfunc), writefunc(_writefunc)
    {
    }

    function<int(psock*, void*, size_t*)> readfunc;
    function<int(psock*, const void*, size_t*)> writefunc;
};

/**
 * \brief Create a dummy psock instance for testing.
 * 
 * \param sock      Pointer to the pointer to receive the socket instance.
 * \param a         Allocator to use for this operation.
 * \param onread    Callback for reads.
 * \param onwrite   Callback for writes.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int dummy_psock_create(
    psock** sock, RCPR_SYM(allocator)* a,
    std::function<int(psock*, void*, size_t*)> onread,
    std::function<int(psock*, const void*, size_t*)> onwrite)
{
    dummy_psock* ctx = new dummy_psock(onread, onwrite);
    status retval;

    retval =
        psock_create_ex(
            sock, a, ctx,
            [](psock* sock, void* c, void* data, size_t* size, bool) {
                dummy_psock* ctx = (dummy_psock*)c;
                return ctx->readfunc(sock, data, size);
            },
            [](psock* sock, void* c, const void* data, size_t* size) {
                dummy_psock* ctx = (dummy_psock*)c;
                return ctx->writefunc(sock, data, size);
            },
            nullptr,
            [](psock*, void* c) {
                dummy_psock* ctx = (dummy_psock*)c;
                delete ctx;
                return STATUS_SUCCESS;
            });

    if (STATUS_SUCCESS != retval)
    {
        delete ctx;
    }

    return retval;
}
