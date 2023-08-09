/**
 * \file inet/vcblockchain_inet_resolve_address.c
 *
 * \brief Resolve an address.
 *
 * \copyright 2023 Velo Payments, Inc.  All rights reserved.
 */

#include <arpa/inet.h>
#include <cbmc/model_assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <rcpr/string.h>
#include <string.h>
#include <vcblockchain/error_codes.h>
#include <vcblockchain/inet.h>

RCPR_IMPORT_string_as(rcpr);

/**
 * \brief Convert an address to a canonial IP form, either as an IPv4 or an IPv6
 * address. 
 *
 * The address can be a fully qualified domain name, a local domain name, or an
 * IP address.
 *
 * \param canonical_addr                Pointer to the character pointer to
 *                                      receive the canonical address on
 *                                      success. This address is allocated with
 *                                      the provided allocator and must be
 *                                      reclaimed when no longer needed.
 * \param alloc                         The allocator to use for this operation.
 * \param query_addr                    The address to query.
 * \param domain                        The domain for this address. It must be
 *                                      AF_INET or AF_INET6.
 *
 * \returns a status code indicating success or failure.
 *      - STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
status FN_DECL_MUST_CHECK vcblockchain_inet_resolve_address(
    char** canonical_addr, RCPR_SYM(allocator)* alloc, const char* query_addr,
    int domain)
{
    status retval;
    struct addrinfo hints;
    struct addrinfo* res;
    char tmp[128];

    /* parameter sanity checks. */
    MODEL_ASSERT(NULL != canonical_addr);
    MODEL_ASSERT(NULL != alloc);
    MODEL_ASSERT(NULL != query_addr);
    MODEL_ASSERT(AF_INET == domain || AF_INET6 == domain);

    /* runtime parameter checks. */
    if (NULL == canonical_addr || NULL == alloc || NULL == query_addr)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto done;
    }

    /* the domain must be AF_INET or AF_INET6. */
    if (AF_INET != domain && AF_INET6 != domain)
    {
        retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
        goto done;
    }

    /* clear hints. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = domain;
    hints.ai_socktype = SOCK_STREAM;

    /* look up the address. */
    retval = getaddrinfo(query_addr, NULL, &hints, &res);
    if (STATUS_SUCCESS != retval)
    {
        retval = VCBLOCKCHAIN_ERROR_INET_RESOLUTION_FAILURE;
        goto done;
    }

    switch (domain)
    {
        case AF_INET:
            /* switch the ipv4 address to presentation format. */
            if (NULL
                    == inet_ntop(
                            AF_INET,
                            &((struct sockaddr_in*)res->ai_addr)->sin_addr, tmp,
                            sizeof(tmp)))
            {
                retval = VCBLOCKCHAIN_ERROR_INET_RESOLUTION_FAILURE;
                goto cleanup_res;
            }
            break;

        case AF_INET6:
            /* switch the ipv6 address to presentation format. */
            if (NULL
                    == inet_ntop(
                            AF_INET6,
                            &((struct sockaddr_in6*)res->ai_addr)->sin6_addr,
                            tmp, sizeof(tmp)))
            {
                retval = VCBLOCKCHAIN_ERROR_INET_RESOLUTION_FAILURE;
                goto cleanup_res;
            }
            break;

        default:
            retval = VCBLOCKCHAIN_ERROR_INVALID_ARG;
            goto cleanup_res;
    }

    /* copy this value to the caller. */
    retval = rcpr_strdup(canonical_addr, alloc, tmp);
    goto cleanup_res;

cleanup_res:
    freeaddrinfo(res);

done:
    memset(tmp, 0, sizeof(tmp));

    return retval;
}
