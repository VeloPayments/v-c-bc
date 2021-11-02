/**
 * \file entity_cert/vcblockchain_entity_public_cert_resource_handle.c
 *
 * \brief Get the resource handle for the given entity certificate.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include "entity_cert_internal.h"

/**
 * \brief Get the resource handle for the given public certificate.
 *
 * \param cert      The private certificate instance to access.
 *
 * \returns the resource handle for this certificate instance.
 */
RCPR_SYM(resource)* vcblockchain_entity_public_cert_resource_handle(
    vcblockchain_entity_public_cert* cert)
{
    MODEL_ASSERT(prop_vcblockchain_entity_public_cert_valid(cert));

    return &cert->hdr;
}
