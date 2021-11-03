/**
 * \file src/ssock/ssock_init_from_host_address.c
 *
 * \brief Initialize a client ssock instance from a server address and port.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vcblockchain/ssock.h>

/**
 * \brief Initialize a client ssock instance from a server address and port.
 *
 * This instance is disposable and must be disposed by calling \ref dispose()
 * when no longer needed.  Note that \ref dispose() will close the socket
 * connection.
 *
 * \param sock              The ssock instance to initialize.
 * \param hostaddr          The host address, which must either be an IP address
 *                          or a DNS resolvable domain.
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
    ssock* sock, const char* hostaddr, unsigned int port)
{
    int retval;
    int sd;
    struct sockaddr_in addr;

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != sock);
    MODEL_ASSERT(NULL != hostaddr);
    MODEL_ASSERT(port < 65536);

    /* runtime parameter checks. */
    if (NULL == sock || NULL == hostaddr || port >= 65536)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto done;
    }

    /* create the socket. */
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0)
    {
        retval = VCBLOCKCHAIN_ERROR_SOCKET_CREATE_FAILED;
        goto done;
    }

    /* set the address family and port. */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    /* resolve the host address. */
    retval = inet_pton(AF_INET, hostaddr, &addr.sin_addr);
    if (1 != retval)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ADDRESS;
        goto cleanup_socket;
    }

    /* attempt to connect to the resolved address and port. */
    retval = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
    if (retval < 0)
    {
        retval = VCBLOCKCHAIN_ERROR_CONNECTION_REFUSED;
        goto cleanup_socket;
    }

    /* turn this into an ssock instance. */
    retval = ssock_init_from_posix(sock, sd);
    if (VCBLOCKCHAIN_STATUS_SUCCESS != retval)
    {
        goto cleanup_socket;
    }

    /* success. */
    goto done;

cleanup_socket:
    close(sd);

done:
    return retval;
}
