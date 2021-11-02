/**
 * \file entity_cert/vcblockchain_entity_private_cert_public_cert_get.c
 *
 * \brief Get a public certificate view of a private entity certificate.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include "entity_cert_internal.h"

/**
 * \brief Get a \ref vcblockchain_entity_public_certificate from a
 * \ref vcblockchain_entity_private_certificate.
 *
 * \param pub       Pointer to the pointer to receive this public entity
 *                  certificate.
 * \param priv      The private entity certificate from which this public
 *                  certificate is accessed.
 *
 * On success \p pub is set to the address of a public certificate instance.
 * This instance is a owned by the private certificate instance \p priv and
 * cannot be used once \p priv is released.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_entity_private_cert_public_cert_get(
    const vcblockchain_entity_public_cert** pub,
    const vcblockchain_entity_private_cert* priv)
{
    MODEL_ASSERT(NULL != pub);
    MODEL_ASSERT(prop_vcblockchain_entity_private_cert_valid(priv));

    *pub = &priv->pub;

    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
