/**
 * \file vcblockchain/ssock.h
 *
 * \brief Simple socket abstraction for vcblockchain.
 *
 * \copyright 2020-2021 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCBLOCKCHAIN_SSOCK_HEADER_GUARD
#define VCBLOCKCHAIN_SSOCK_HEADER_GUARD

#include <stddef.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/ssock/data.h>
#include <vccrypt/suite.h>
#include <vpr/allocator.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief Initialize a ssock instance from a POSIX socket descriptor.
 *
 * This instance takes over ownership of the socxet descriptor. This instance is
 * disposable and must be disposed by calling \ref dispose() when no longer
 * needed.  Note that \ref dispose() will close the underlying socket
 * descriptor.
 *
 * \param sock              The ssock instance to initialize.
 * \param sd                The socket descriptor to use for this instance.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - a non-zero error code on failure.
 */
int ssock_init_from_posix(ssock* sock, int sd);

/**
 * \brief Initialize a client ssock instance from a server address and port.
 *
 * This instance is disposable and must be disposed by calling \ref dispose()
 * when no longer needed.  Note that \ref dispose() will close the socket
 * connection.
 *
 * \param sock              The ssock instance to initialize.
 * \param hostaddr          The host address, which must be a presentation IP
 *                          address.
 * \param port              The port for the connection.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if one of the arguments is invalid.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ADDRESS if the address could not be
 *        resolved.
 *      - VCBLOCKCHAIN_ERROR_CONNECTION_REFUSED if the connection could not be
 *        established.
 *      - a non-zero error code on failure.
 */
int ssock_init_from_host_address(
    ssock* sock, const char* hostaddr, unsigned int port);

/**
 * \brief Read data from a ssock instance.
 *
 * \param sock      The ssock instance to read from.
 * \param buf       The buffer to read bytes into.
 * \param size      Pointer to the size value. As input, it is the number of
 *                  bytes to read from this ssock.  On success, the number of
 *                  bytes read will be saved to this variable.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - a non-zero error code on failure.
 */
int ssock_read(ssock* sock, void* buf, size_t* size);

/**
 * \brief Write data to a ssock instance.
 *
 * \param sock      The ssock instance to write to.
 * \param buf       The buffer to write bytes into the socket from.
 * \param size      Pointer to the size value. As input, it is the number of
 *                  bytes to write to this ssock.  On success, the number of
 *                  bytes written will be saved to this variable.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - a non-zero error code on failure.
 */
int ssock_write(ssock* sock, const void* buf, size_t* size);

/**
 * \brief Write a data packet.
 *
 * On success, the data packet value will be written, along with type
 * information and size.
 *
 * \param sock          The \ref ssock socket to which data is written.
 * \param val           The data to write.
 * \param size          The size of the data to write.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing data failed.
 */
int ssock_write_data(ssock* sock, const void* val, uint32_t size);

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
    vccrypt_suite_options_t* suite, vccrypt_buffer_t* secret);

/**
 * \brief Write a character string to the socket.
 *
 * On success, the character string value is written, along with type
 * information and size.
 *
 * \param sock          The \ref ssock socket to which data is written.
 * \param val           The string to write.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing data failed.
 */
int ssock_write_string(ssock* sock, const char* val);

/**
 * \brief Write a uint64_t value to the socket.
 *
 * On success, the value is written, along with type information and size.
 *
 * \param sock          The \ref ssock socket to which data is written.
 * \param val           The value to write.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing data failed.
 */
int ssock_write_uint64(ssock* sock, uint64_t val);

/**
 * \brief Write an int64_t value to the socket.
 *
 * On success, the value is written, along with type information and size.
 *
 * \param sock          The \ref ssock socket to which data is written.
 * \param val           The value to write.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing data failed.
 */
int ssock_write_int64(ssock* sock, int64_t val);

/**
 * \brief Write a uint8_t value to the socket.
 *
 * On success, the value is written, along with type information and size.
 *
 * \param sock          The \ref ssock socket to which data is written.
 * \param val           The value to write.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing data failed.
 */
int ssock_write_uint8(ssock* sock, uint8_t val);

/**
 * \brief Write an int8_t value to the socket.
 *
 * On success, the value is written, along with type information and size.
 *
 * \param sock          The \ref ssock socket to which data is written.
 * \param val           The value to write.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_WRITE if writing data failed.
 */
int ssock_write_int8(ssock* sock, int8_t val);

/**
 * \brief Read a data packet from the socket.
 *
 * On success, a data buffer is allocated and read, along with type
 * information and size.  The caller owns this buffer and is responsible for
 * releasing it to the allocator when it is no longer in use.
 *
 * \param sock          The \ref ssock socket from which data is read.
 * \param alloc_opts    The allocator options to use for this read.
 * \param val           Pointer to the pointer of the data buffer.
 * \param size          Pointer to the variable to receive the size of this
 *                      packet.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 */
int ssock_read_data(
    ssock* sock, allocator_options_t* alloc_opts, void** val, uint32_t* size);

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
    vccrypt_buffer_t* secret);

/**
 * \brief Read a character string from the socket.
 *
 * On success, a character string value is allocated and read, along with type
 * information and size.  The caller owns this character string and is
 * responsible for releasing it to the allocator it when it is no longer in use.
 *
 * \param sock          The \ref ssock socket from which data is read.
 * \param alloc_opts    The allocator options to use for this read.
 * \param val           Pointer to the string pointer to hold the string value
 *                      on success.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_SIZE if the data size is
 *        wrong.
 *      - VCBLOCKCHAIN_ERROR_OUT_OF_MEMORY if this operation encountered an
 *        out-of-memory error.
 */
int ssock_read_string(ssock* sock, allocator_options_t* alloc_opts, char** val);

/**
 * \brief Read a uint64_t value from the socket.
 *
 * On success, the value is read, along with type information and size.
 *
 * \param sock          The \ref ssock socket from which data is read.
 * \param val           Pointer to hold the value.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_SIZE if the data size
 *        read from the socket was unexpected.
 */
int ssock_read_uint64(ssock* sock, uint64_t* val);

/**
 * \brief Read an int64_t value from the socket.
 *
 * On success, the value is read, along with type information and size.
 *
 * \param sock          The \ref ssock socket from which data is read.
 * \param val           Pointer to hold the value.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_SIZE if the data size
 *        read from the socket was unexpected.
 */
int ssock_read_int64(ssock* sock, int64_t* val);

/**
 * \brief Read a uint8_t value from the socket.
 *
 * On success, the value is read, along with type information and size.
 *
 * \param sock          The \ref ssock socket from which data is read.
 * \param val           Pointer to hold the value.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_SIZE if the data size
 *        read from the socket was unexpected.
 */
int ssock_read_uint8(ssock* sock, uint8_t* val);

/**
 * \brief Read an int8_t value from the socket.
 *
 * On success, the value is read, along with type information and size.
 *
 * \param sock          The \ref ssock socket from which data is read.
 * \param val           Pointer to hold the value.
 *
 * \returns A status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - VCBLOCKCHAIN_ERROR_INVALID_ARG if a runtime argument check failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ if a read on the socket failed.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_TYPE if the data type
 *        read from the socket was unexpected.
 *      - VCBLOCKCHAIN_ERROR_SSOCK_READ_UNEXPECTED_DATA_SIZE if the data size
 *        read from the socket was unexpected.
 */
int ssock_read_int8(ssock* sock, int8_t* val);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCBLOCKCHAIN_SSOCK_HEADER_GUARD*/
