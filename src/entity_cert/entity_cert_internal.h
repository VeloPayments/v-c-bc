/**
 * \file entity_cert/entity_cert_internal.h
 *
 * \brief Internal methods and definitions for entity_cert.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCBLOCKCHAIN_ENTITY_CERT_INTERNAL_HEADER_GUARD
#define VCBLOCKCHAIN_ENTITY_CERT_INTERNAL_HEADER_GUARD

#include <vcblockchain/entity_cert.h>
#include <rcpr/resource/protected.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief An entity public certificate.
 */
struct vcblockchain_entity_public_cert
{
    RCPR_SYM(resource) hdr;
    RCPR_SYM(rcpr_uuid) artifact_id;
    vccrypt_buffer_t public_encryption_key;
    vccrypt_buffer_t public_signing_key;

    RCPR_MODEL_STRUCT_TAG(vcblockchain_entity_public_cert);
};

/**
 * \brief An entity private certificate.
 */
struct vcblockchain_entity_private_cert
{
    vcblockchain_entity_public_cert pub;
    vccrypt_buffer_t private_encryption_key;
    vccrypt_buffer_t private_signing_key;

    RCPR_MODEL_STRUCT_TAG(vcblockchain_entity_private_cert);
};

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCBLOCKCHAIN_ENTITY_CERT_INTERNAL_HEADER_GUARD*/
