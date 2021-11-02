/**
 * \file vcblockchain/entity_cert.h
 *
 * \brief Interface and methods for \ref entity_public_cert and
 * \ref entity_private_cert.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#ifndef VCBLOCKCHAIN_ENTITY_CERT_HEADER_GUARD
#define VCBLOCKCHAIN_ENTITY_CERT_HEADER_GUARD

#include <vccrypt/suite.h>
#include <rcpr/resource.h>
#include <rcpr/uuid.h>

/* make this header C++ friendly. */
#ifdef __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief An entity private certificate.
 */
typedef struct vcblockchain_entity_private_cert
vcblockchain_entity_private_cert;

/**
 * \brief An entity public certificate.
 */
typedef struct vcblockchain_entity_public_cert
vcblockchain_entity_public_cert;

/**
 * \brief Create a \ref vcblockchain_entity_private_certificate from a
 * \ref vccrypt_buffer_t.
 *
 * \param priv      Pointer to the pointer to receive this private entity
 *                  certificate.
 * \param suite     The crypto suite to use for this operation.
 * \param buffer    The buffer containing the unencrypted certificate.
 *
 * On success \p priv is set to the address of a private certificate instance.
 * This instance is a \ref resource that is owned by the caller and must be
 * released by calling \ref resource_release on its resource handle when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_entity_private_cert_decode(
    vcblockchain_entity_private_cert** priv, vccrypt_suite_options_t* suite,
    const vccrypt_buffer_t* buffer);

/**
 * \brief Create a \ref vcblockchain_entity_public_certificate from a
 * \ref vccrypt_buffer_t.
 *
 * \param pub       Pointer to the pointer to receive this public entity
 *                  certificate.
 * \param suite     The crypto suite to use for this operation.
 * \param buffer    The buffer containing the unencrypted certificate.
 *
 * On success \p pub is set to the address of a public certificate instance.
 * This instance is a \ref resource that is owned by the caller and must be
 * released by calling \ref resource_release on its resource handle when it is
 * no longer needed.
 *
 * \returns a status code indicating success or failure.
 *      - VCBLOCKCHAIN_STATUS_SUCCESS on success.
 *      - a non-zero error code on failure.
 */
int vcblockchain_entity_public_cert_decode(
    vcblockchain_entity_public_cert** pub, vccrypt_suite_options_t* suite,
    const vccrypt_buffer_t* buffer);

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
    const vcblockchain_entity_private_cert* priv);

/**
 * \brief Get the public encryption key buffer for any entity.
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
int vcblockchain_entity_get_public_encryption_key(
    const vccrypt_buffer_t** buf, const void* ent);

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
    const vccrypt_buffer_t** buf, const void* ent);

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
    const RCPR_SYM(rcpr_uuid)** buf, const void* ent);

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
int vcblockchain_entity_private_cert_get_public_encryption_key(
    const vccrypt_buffer_t** buf, const vcblockchain_entity_private_cert* ent);

/**
 * \brief Get the private signing key buffer for a private entity certificate.
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
int vcblockchain_entity_private_cert_get_public_signing_key(
    const vccrypt_buffer_t** buf, const vcblockchain_entity_private_cert* ent);

/**
 * \brief Get the resource handle for the given private certificate.
 *
 * \param cert      The private certificate instance to access.
 *
 * \returns the resource handle for this certificate instance.
 */
RCPR_SYM(resource)* vcblockchain_entity_private_cert_resource_handle(
    vcblockchain_entity_private_cert* cert);

/**
 * \brief Get the resource handle for the given public certificate.
 *
 * \param cert      The private certificate instance to access.
 *
 * \returns the resource handle for this certificate instance.
 */
RCPR_SYM(resource)* vcblockchain_entity_public_cert_resource_handle(
    vcblockchain_entity_public_cert* cert);

/**
 * \brief Return true if the given entity private certificate is valid.
 *
 * \param cert      The private certificate instance to check.
 *
 * \note This function is only available at model check time.
 *
 * \returns true if the instance is valid.
 */
bool prop_vcblockchain_entity_private_cert_valid(
    const vcblockchain_entity_private_cert* cert);

/**
 * \brief Return true if the given entity public certificate is valid.
 *
 * \param cert      The public certificate instance to check.
 *
 * \note This function is only available at model check time.
 *
 * \returns true if the instance is valid.
 */
bool prop_vcblockchain_entity_public_cert_valid(
    const vcblockchain_entity_public_cert* cert);

/* make this header C++ friendly. */
#ifdef __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCBLOCKCHAIN_ENTITY_CERT_HEADER_GUARD*/
