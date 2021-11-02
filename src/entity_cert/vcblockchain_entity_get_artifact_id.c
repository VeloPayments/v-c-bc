/**
 * \file entity_cert/vcblockchain_entity_get_artifact_id.c
 *
 * \brief Get the artifact id of the given entity.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include "entity_cert_internal.h"

/**
 * \brief Get the artifact id for any entity.
 *
 * \param id        Pointer to the pointer to receive the uuid pointer.
 * \param ent       Pointer to either a public or private entity.
 *
 * On success \p id is set to the address of the artifact id for this entity.
 * This id is owned by the entity certificate instance \p ent and
 * cannot be used once \p ent is released.  \p ent must be either a \ref
 * vcblockchain_entity_public_cert or a \ref vcblockchain_entity_private_cert.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_entity_get_artifact_id(
    const RCPR_SYM(rcpr_uuid)** id, const void* ent)
{
    vcblockchain_entity_public_cert* cert =
        (vcblockchain_entity_public_cert*)ent;

    MODEL_ASSERT(NULL != buf);
    MODEL_ASSERT(prop_vcblockchain_entity_public_cert_valid(cert));

    *id = &cert->artifact_id;

    return VCBLOCKCHAIN_STATUS_SUCCESS;
}
