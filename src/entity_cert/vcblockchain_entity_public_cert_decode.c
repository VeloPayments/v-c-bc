/**
 * \file entity_cert/vcblockchain_entity_public_cert_decode.c
 *
 * \brief Decode a public certificate stream into an entity public cert
 * instance.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <string.h>
#include <vccert/fields.h>
#include <vccert/parser.h>
#include <vpr/parameters.h>

#include "entity_cert_internal.h"

RCPR_IMPORT_resource;

/* forward decls. */
static status vcblockchain_entity_public_cert_resource_release(resource* r);

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
    const vccrypt_buffer_t* buffer)
{
    int retval;
    vcblockchain_entity_public_cert* tmp = NULL;
    vccert_parser_options_t parser_options;
    vccert_parser_context_t parser;

    MODEL_ASSERT(NULL != priv);
    MODEL_ASSERT(prop_vccrypt_suite_valid(suite));
    MODEL_ASSERT(prop_vccrypt_buffer_valid(buffer));

    /* create simple parser options. */
    retval =
        vccert_parser_options_simple_init(
            &parser_options, suite->alloc_opts, suite);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        goto done;
    }

    /* create a parser. */
    retval =
        vccert_parser_init(
            &parser_options, &parser, buffer->data, buffer->size);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        goto cleanup_parser_options;
    }

    /* get the artifact id. */
    const uint8_t* artifact_id_value = NULL;
    size_t artifact_id_size = 0U;
    retval =
        vccert_parser_find_short(
            &parser, VCCERT_FIELD_TYPE_ARTIFACT_ID,
            &artifact_id_value, &artifact_id_size);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        goto cleanup_parser;
    }

    /* verify the artifact id. */
    size_t expected_uuid_size = 16;
    if (artifact_id_size != expected_uuid_size)
    {
        retval = VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE;
        goto cleanup_parser;
    }

    /* get the public encryption key. */
    const uint8_t* public_encryption_key_value = NULL;
    size_t public_encryption_key_size = 0U;
    retval =
        vccert_parser_find_short(
            &parser, VCCERT_FIELD_TYPE_PUBLIC_ENCRYPTION_KEY,
            &public_encryption_key_value, &public_encryption_key_size);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        goto cleanup_parser;
    }

    /* verify the public encryption key size. */
    size_t expected_pubkey_size = suite->key_cipher_opts.public_key_size;
    if (public_encryption_key_size != expected_pubkey_size)
    {
        retval = VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE;
        goto cleanup_parser;
    }

    /* get the public signing key. */
    const uint8_t* public_signing_key_value = NULL;
    size_t public_signing_key_size = 0U;
    retval =
        vccert_parser_find_short(
            &parser, VCCERT_FIELD_TYPE_PUBLIC_SIGNING_KEY,
            &public_signing_key_value, &public_signing_key_size);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        goto cleanup_parser;
    }

    /* verify the public signing key size. */
    size_t expected_sign_pubkey_size = suite->sign_opts.public_key_size;
    if (public_signing_key_size != expected_sign_pubkey_size)
    {
        retval = VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE;
        goto cleanup_parser;
    }

    /* allocate memory for the entity instance. */
    tmp = (vcblockchain_entity_public_cert*)
        allocate(suite->alloc_opts, sizeof(vcblockchain_entity_public_cert));
    if (NULL == tmp)
    {
        goto cleanup_parser;
    }

    /* initialize the resource. */
    resource_init(
        &tmp->hdr, &vcblockchain_entity_public_cert_resource_release);

    /* copy the allocator. */
    tmp->alloc_opts = suite->alloc_opts;

    /* copy the artifact id. */
    memcpy(tmp->artifact_id.data, artifact_id_value, artifact_id_size);

    /* create the public encryption key buffer. */
    retval =
        vccrypt_buffer_init(
            &tmp->public_encryption_key, suite->alloc_opts,
            public_encryption_key_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto free_tmp;
    }

    /* copy the public encryption key. */
    memcpy(
        tmp->public_encryption_key.data, public_encryption_key_value,
        public_encryption_key_size);

    /* create the public signing key buffer. */
    retval =
        vccrypt_buffer_init(
            &tmp->public_signing_key, suite->alloc_opts,
            public_signing_key_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_public_encryption_key;
    }

    /* copy the public signing key. */
    memcpy(
        tmp->public_signing_key.data, public_signing_key_value,
        public_signing_key_size);

    /* success. set pub to tmp. */
    *pub = tmp;
    retval = STATUS_SUCCESS;
    goto cleanup_parser;

cleanup_public_encryption_key:
    dispose((disposable_t*)&tmp->public_encryption_key);

free_tmp:
    memset(tmp, 0, sizeof(*tmp));
    release(suite->alloc_opts, tmp);

cleanup_parser:
    dispose((disposable_t*)&parser);

cleanup_parser_options:
    dispose((disposable_t*)&parser_options);

done:
    return retval;
}

/**
 * \brief Release the public entity certificate resource.
 */
static status vcblockchain_entity_public_cert_resource_release(resource* r)
{
    vcblockchain_entity_public_cert* cert =
        (vcblockchain_entity_public_cert*)r;

    /* cache the allocator. */
    allocator_options_t* alloc_opts = cert->alloc_opts;

    /* dispose all buffers. */
    dispose((disposable_t*)&cert->public_encryption_key);
    dispose((disposable_t*)&cert->public_signing_key);

    /* clear the structure. */
    memset(cert, 0, sizeof(*cert));

    /* release the structure. */
    release(alloc_opts, cert);

    /* success. */
    return STATUS_SUCCESS;
}
