/**
 * \file ssock/ssock_write_authed_data.c
 *
 * \brief Write an authenticated data packet to a socket.
 *
 * \copyright 2020 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <string.h>
#include <vcblockchain/ssock.h>

/**
 * \brief Write an authenticated data packet.
 *
 * On success, the authenticated data packet value will be written, along with
 * type information and size.
 *
 * \param sock          The \ref ssock socket to which data is written.
 * \param iv            The 64-bit IV to use for this packet.
 * \param val           The payload data to write.
 * \param size          The size of the payload data to write.
 * \param suite         The crypto suite to use for authenticating this packet.
 * \param secret        The shared secret between the peer and host.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing data failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_AUTHED_INVALID_CRYPTO_SUITE if the crypto
 *        suite is invalid.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_AUTHED_INVALID_SECRET if the secret key is
 *        invalid.
 */
int ssock_write_authed_data(
    ssock* sock, uint64_t iv, const void* val, uint32_t size,
    vccrypt_suite_options_t* suite, vccrypt_buffer_t* secret)
{
    uint8_t type = SSOCK_DATA_TYPE_AUTHED_PACKET;
    uint32_t nsize = htonl(size);
    int retval = 0;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != val);
    MODEL_ASSERT(NULL != suite);
    MODEL_ASSERT(NULL != secret);

    /* runtime parameter checks. */
    if (NULL == sock || NULL == val || NULL == suite || NULL == secret)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto done;
    }

    /* create a buffer for holding the digest. */
    vccrypt_buffer_t digest;
    retval = 
        vccrypt_suite_buffer_init_for_mac_authentication_code(
            suite, &digest, true);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* create a packet buffer large enough for this authed packet. */
    size_t packet_size =
        sizeof(type) + sizeof(nsize) + digest.size + size;
    vccrypt_buffer_t packet;
    retval =
        vccrypt_buffer_init(&packet, suite->alloc_opts, packet_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_digest;
    }

    /* create a stream cipher for encrypting this packet. */
    vccrypt_stream_context_t stream;
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_suite_stream_init(suite, &stream, secret))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_packet;
    }

    /* create a mac instance for building the packet authentication code. */
    vccrypt_mac_context_t mac;
    if (VCCRYPT_STATUS_SUCCESS !=
        vccrypt_suite_mac_short_init(suite, &mac, secret))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_stream;
    }

    /* start the stream cipher. */
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_stream_continue_encryption(&stream, &iv, sizeof(iv), 0))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_mac;
    }

    /* create a byte pointer for convenience. */
    uint8_t* bpacket = (uint8_t*)packet.data;
    size_t offset = 0;

    /* encrypt the type. */
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_stream_encrypt(
                &stream, &type, sizeof(type), bpacket, &offset))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_mac;
    }

    /* encrypt the size. */
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_stream_encrypt(
                &stream, &nsize, sizeof(nsize), bpacket, &offset))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_mac;
    }

    /* encrypt the payload. */
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_stream_encrypt(
                &stream, val, size, bpacket + digest.size, &offset))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_mac;
    }

    /* digest the packet header and payload. */
    if (VCCRYPT_STATUS_SUCCESS !=
            vccrypt_mac_digest(
                &mac, bpacket, sizeof(type) + sizeof(nsize)) ||
        VCCRYPT_STATUS_SUCCESS !=
            vccrypt_mac_digest(
                &mac, bpacket + sizeof(type) + sizeof(nsize) + digest.size,
                size))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_mac;
    }

    /* finalize the digest. */
    if (VCCRYPT_STATUS_SUCCESS != vccrypt_mac_finalize(&mac, &digest))
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_CRYPTO;
        goto cleanup_mac;
    }

    /* copy the digest to the packet. */
    memcpy(bpacket + sizeof(type) + sizeof(nsize), digest.data, digest.size);

    /* write the packet to the socket. */
    size_t write_size = packet.size;
    retval = ssock_write(sock, packet.data, &write_size);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval || write_size != packet.size)
    {
        retval = VCBLOCKCHAIN_ERROR_SSOCK_WRITE;
        goto cleanup_mac;
    }

    /* success. */
    retval = VCBLOCKCHAIN_STATUS_SUCCESS;
    /* fall-through. */

cleanup_mac:
    dispose((disposable_t*)&mac);

cleanup_stream:
    dispose((disposable_t*)&stream);

cleanup_packet:
    dispose((disposable_t*)&packet);

cleanup_digest:
    dispose((disposable_t*)&digest);

done:
    return retval;
}
