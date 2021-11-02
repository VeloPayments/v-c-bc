/**
 * \file
 * entity_cert/vcblockchain_entity_private_cert_get_private_encryption_key.c
 *
 * \brief Get the private encryption key for the given private entity cert.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include "entity_cert_internal.h"

/**
 * \brief Get the private encryption key buffer for a private entity
 * certificate.
 *
 * \param buf       Pointer to the pointer to receive the buffer pointer.
 * \param priv      Pointer to the private entity certificate.
 *
 * On success \p buf is set to the address of the private key buffer for this
 * entity. This buffer is owned by the entity certificate instance \p ent and
 * cannot be used once \p ent is released.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_entity_private_cert_get_private_encryption_key(
    const vccrypt_buffer_t** buf, const vcblockchain_entity_private_cert* ent)
{
    MODEL_ASSERT(NULL != buf);
    MODEL_ASSERT(prop_vcblockchain_entity_private_cert_valid(ent));

    *buf = &ent->private_encryption_key;

    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
