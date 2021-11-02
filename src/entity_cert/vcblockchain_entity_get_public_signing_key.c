/**
 * \file entity_cert/vcblockchain_entity_get_public_signing_key.c
 *
 * \brief Get the public signing key of the given entity.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include "entity_cert_internal.h"

/**
 * \brief Get the public signing key buffer for any entity.
 *
 * \param buf       Pointer to the pointer to receive the buffer pointer.
 * \param ent       Pointer to either a public or private entity.
 *
 * On success \p buf is set to the address of the public key buffer for this
 * entity. This buffer is owned by the entity certificate instance \p ent and
 * cannot be used once \p ent is released.  \p ent must be either a \ref
 * vcblockchain_entity_public_cert or a \ref vcblockchain_entity_private_cert.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_entity_get_public_signing_key(
    const vccrypt_buffer_t** buf, const void* ent)
{
    vcblockchain_entity_public_cert* cert =
        (vcblockchain_entity_public_cert*)ent;

    MODEL_ASSERT(NULL != buf);
    MODEL_ASSERT(prop_vcblockchain_entity_public_cert_valid(cert));

    *buf = &cert->public_signing_key;

    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
