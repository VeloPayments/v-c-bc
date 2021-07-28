/**
 * \file ssock/ssock_read_authed_data.c
 *
 * \brief Read an authenticated data packet from a socket.
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/ssock.h>
#include <vccrypt/compare.h>

/**
 * \brief Read an authenticated data packet from the socket.
 *
 * On success, an authenticated data buffer is allocated and read, along with
 * type information and size.  The caller owns this buffer and is responsible
 * for releasing it to the allocator when it is no longer in use.
 *
 * \param sock          The \ref ssock socket from which data is read.
 * \param alloc_opts    The allocator options to use for this read.
 * \param iv            The 64-bit IV to expect for this packet.
 * \param val           Pointer to the pointer of the data buffer.
 * \param size          Pointer to the variable to receive the size of this
 *                      packet.
 * \param suite         The crypto suite to use for authenticating this packet.
 * \param secret        The shared secret between the peer and host.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_AUTHED_INVALID_CRYPTO_SUITE if the crypto
 *        suite is invalid.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_AUTHED_INVALID_SECRET if the secret key is
 *        invalid.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_AUTHENTICATION_FAILURE if the packet could
 *        not be authenticated.
 */
int ssock_read_authed_data(
    ssock* sock, allocator_options_t* alloc_opts, uint64_t iv, void** val,
    uint32_t* size, vccrypt_suite_options_t* suite,
    vccrypt_buffer_t* secret)
{
    int retval = 0;
    uint32_t type = 0U;
    uint32_t nsize = 0U;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != alloc_opts);
    MODEL_ASSERT(NULL != val);
    MODEL_ASSERT(NULL != size);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != secret);

    /* runtime parameter checks. */
    if (    NULL == sock || NULL == alloc_opts || NULL == val || NULL == size
         || NULL == suite || NULL == secret)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto done;
    }

    /* attempt to allocate space for the header. */
    size_t header_size =
          sizeof(type)
        + sizeof(nsize)
        + suite->mac_short_opts.mac_size;
    vccrypt_buffer_t hbuffer;
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_buffer_init(&hbuffer, alloc_opts, header_size))
    {
        retval = VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    /* attempt to allocate space for the decrypted header. */
    size_t dheader_size = sizeof(type) + sizeof(nsize);
    vccrypt_buffer_t dhbuffer;
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_buffer_init(&dhbuffer, alloc_opts, dheader_size))
    {
        retval = VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
        goto cleanup_hbuffer;
    }

    /* set up pointers for convenience. */
    uint8_t* header = (uint8_t*)hbuffer.data;
    uint8_t* dheader = (uint8_t*)dhbuffer.data;

    /* attempt to read the header. */
    size_t header_read_size = header_size;
    if (VCBLOCKCHAIN_STATUS_SUCCESS !=
            ssock_read(sock, hbuffer.data, &header_read_size)
        || header_read_size != header_size)
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_READ;
        goto cleanup_dhbuffer;
    }

    /* set up the stream cipher. */
    vccrypt_stream_context_t stream;
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_suite_stream_init(suite, &stream, secret))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_dhbuffer;
    }

    /* set up the MAC. */
    vccrypt_mac_context_t mac;
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_suite_mac_short_init(suite, &mac, secret))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_stream;
    }

    /* start decryption of the stream. */
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_stream_continue_decryption(&stream, &iv, sizeof(iv), 0))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_mac;
    }

    /* decrypt enough of the header to determine the type and size. */
    size_t offset = 0;
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_stream_decrypt(
                &stream, hbuffer.data, dheader_size, dhbuffer.data, &offset))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_mac;
    }

    /* verify that the type is SSOCK_DATA_TYPE_AUTHED_PACKET. */
    memcpy(&type, dheader, sizeof(type));
    if (SSOCK_DATA_TYPE_AUTHED_PACKET != ntohl(type))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_UNAUTHORIZED_PACKET;
        goto cleanup_mac;
    }

    /* verify that the size makes sense. */
    memcpy(&nsize, dheader + sizeof(type), sizeof(nsize));
    *size = ntohl(nsize);
    if (*size > 10ULL * 1024ULL * 1024ULL /* 10 MB */)
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_UNAUTHORIZED_PACKET;
        goto cleanup_mac;
    }

    /* create a payload packet for holding the payload. */
    vccrypt_buffer_t payload;
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_buffer_init(&payload, alloc_opts, *size))
    {
        retval = VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
        goto cleanup_mac;
    }

    /* read the payload. */
    size_t read_size = *size;
    if (VCBLOCKCHAIN_STATUS_SUCCESS !=
            ssock_read(sock, payload.data, &read_size)
         || read_size != *size)
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_READ;
        goto cleanup_payload_buffer;
    }

    /* digest the packet. */
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_mac_digest(&mac, hbuffer.data, dheader_size)
     || VCCRYPT_STATUS_SUCCESS !=
            vccrypt_mac_digest(&mac, payload.data, *size))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_payload_buffer;
    }

    /* create a buffer to hold the digest. */
    vccrypt_buffer_t digest;
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_suite_buffer_init_for_mac_authentication_code(
                suite, &digest, true))
    {
        retval = VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
        goto cleanup_payload_buffer;
    }

    /* finalize the mac. */
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_mac_finalize(&mac, &digest))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_digest;
    }

    /* compare the digest with the mac in the packet. */
    if (0 !=
            crypto_memcmp(
                digest.data, header + sizeof(type) + sizeof(nsize),
                digest.size))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_UNAUTHORIZED_PACKET;
        goto cleanup_digest;
    }

    /* the payload has been authenticated. create the output buffer. */
    *val = allocate(alloc_opts, *size);
    if (NULL == *val)
    {
        retval = VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY;
        goto cleanup_digest;
    }

    /* continue decryption in the payload. */
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_stream_continue_decryption(
                &stream, &iv, sizeof(iv), offset))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_val;
    }

    /* reset the offset. */
    offset = 0;

    /* decrypt the payload. */
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_stream_decrypt(
                &stream, payload.data, *size, *val, &offset))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_val;
    }

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;
    /* on success, the caller owns the buffer allocated in val. */
    goto cleanup_digest;

cleanup_val:
    memset(*val, 0, *size);
    release(alloc_opts, *val);
    *val = NULL;

cleanup_digest:
    dispose((disposable_t*)&digest);

cleanup_payload_buffer:
    dispose((disposable_t*)&payload);

cleanup_mac:
    dispose((disposable_t*)&mac);

cleanup_stream:
    dispose((disposable_t*)&stream);

cleanup_dhbuffer:
    dispose((disposable_t*)&dhbuffer);

cleanup_hbuffer:
    dispose((disposable_t*)&hbuffer);

done:
    return retval;
}
