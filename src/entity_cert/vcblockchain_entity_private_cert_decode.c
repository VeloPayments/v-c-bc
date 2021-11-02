/**
 * \file entity_cert/vcblockchain_entity_private_cert_decode.c
 *
 * \brief Decode a private certificate stream into an entity private cert
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
static bool dummy_txn_resolver(
    void*, void*, const uint8_t*, const uint8_t*, vccrypt_buffer_t*, bool*);
static int32_t dummy_artifact_state_resolver(
    void*, void*, const uint8_t*, vccrypt_buffer_t*);
static int dummy_contract_resolver(
    void*, void*, const uint8_t*, const uint8_t*, vccert_contract_closure_t*);
static bool dummy_key_resolver(
    void*, void*, uint64_t, const uint8_t*, vccrypt_buffer_t*,
    vccrypt_buffer_t*);
static status vcblockchain_entity_private_cert_resource_release(resource* r);

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
    const vccrypt_buffer_t* buffer)
{
    int retval;
    vcblockchain_entity_private_cert* tmp = NULL;
    vccert_parser_options_t parser_options;
    vccert_parser_context_t parser;

    MODEL_ASSERT(NULL != priv);
    MODEL_ASSERT(prop_vccrypt_suite_valid(suite));
    MODEL_ASSERT(prop_vccrypt_buffer_valid(buffer));

    /* create simple parser options. */
    retval =
        vccert_parser_options_init(
            &parser_options, suite->alloc_opts, suite, &dummy_txn_resolver,
            &dummy_artifact_state_resolver, &dummy_contract_resolver,
            &dummy_key_resolver, NULL);
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

    /* get the private encryption key. */
    const uint8_t* private_encryption_key_value = NULL;
    size_t private_encryption_key_size = 0U;
    retval =
        vccert_parser_find_short(
            &parser, VCCERT_FIELD_TYPE_PRIVATE_ENCRYPTION_KEY,
            &private_encryption_key_value, &private_encryption_key_size);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        goto cleanup_parser;
    }

    /* verify the private encryption key size. */
    size_t expected_enc_privkey_size = suite->key_cipher_opts.private_key_size;;
    if (private_encryption_key_size != expected_enc_privkey_size)
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

    /* get the private signing key. */
    const uint8_t* private_signing_key_value = NULL;
    size_t private_signing_key_size = 0U;
    retval =
        vccert_parser_find_short(
            &parser, VCCERT_FIELD_TYPE_PRIVATE_SIGNING_KEY,
            &private_signing_key_value, &private_signing_key_size);
    if (VCCERT_STATUS_SUCCESS != retval)
    {
        goto cleanup_parser;
    }

    /* verify the private signing key size. */
    size_t expected_sign_privkey_size = suite->sign_opts.private_key_size;;
    if (private_signing_key_size != expected_sign_privkey_size)
    {
        retval = VCCERT_ERROR_PARSER_FIELD_INVALID_FIELD_SIZE;
        goto cleanup_parser;
    }

    /* allocate memory for the entity instance. */
    tmp = (vcblockchain_entity_private_cert*)
        allocate(suite->alloc_opts, sizeof(vcblockchain_entity_private_cert));
    if (NULL == tmp)
    {
        goto cleanup_parser;
    }

    /* initialize the resource. */
    resource_init(
        &tmp->pub.hdr, &vcblockchain_entity_private_cert_resource_release);

    /* copy the allocator. */
    tmp->pub.alloc_opts = suite->alloc_opts;

    /* copy the artifact id. */
    memcpy(tmp->pub.artifact_id.data, artifact_id_value, artifact_id_size);

    /* create the public encryption key buffer. */
    retval =
        vccrypt_buffer_init(
            &tmp->pub.public_encryption_key, suite->alloc_opts,
            public_encryption_key_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto free_tmp;
    }

    /* copy the public encryption key. */
    memcpy(
        tmp->pub.public_encryption_key.data, public_encryption_key_value,
        public_encryption_key_size);

    /* create the public signing key buffer. */
    retval =
        vccrypt_buffer_init(
            &tmp->pub.public_signing_key, suite->alloc_opts,
            public_signing_key_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_public_encryption_key;
    }

    /* copy the public signing key. */
    memcpy(
        tmp->pub.public_signing_key.data, public_signing_key_value,
        public_signing_key_size);

    /* create the private encryption key buffer. */
    retval =
        vccrypt_buffer_init(
            &tmp->private_encryption_key, suite->alloc_opts,
            private_encryption_key_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_public_signing_key;
    }

    /* copy the private encryption key. */
    memcpy(
        tmp->private_encryption_key.data, private_encryption_key_value,
        private_encryption_key_size);

    /* create the private signing key buffer. */
    retval =
        vccrypt_buffer_init(
            &tmp->private_signing_key, suite->alloc_opts,
            private_signing_key_size);
    if (VCCRYPT_STATUS_SUCCESS != retval)
    {
        goto cleanup_private_encryption_key;
    }

    /* copy the private signing key. */
    memcpy(
        tmp->private_signing_key.data, private_signing_key_value,
        private_signing_key_size);

    /* success. set priv to tmp. */
    *priv = tmp;
    retval = STATUS_SUCCESS;
    goto cleanup_parser;

cleanup_private_encryption_key:
    dispose((disposable_t*)&tmp->private_encryption_key);

cleanup_public_signing_key:
    dispose((disposable_t*)&tmp->pub.public_signing_key);

cleanup_public_encryption_key:
    dispose((disposable_t*)&tmp->pub.public_encryption_key);

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
 * \brief Dummy transaction resolver for parser options.
 */
static bool dummy_txn_resolver(
    void* UNUSED(a), void* UNUSED(b), const uint8_t* UNUSED(c),
    const uint8_t* UNUSED(d), vccrypt_buffer_t* UNUSED(e), bool* UNUSED(f))
{
    return false;
}

/**
 * \brief Dummy artifact state resolver for parser options.
 */
static int32_t dummy_artifact_state_resolver(
    void* UNUSED(a), void* UNUSED(b), const uint8_t* UNUSED(c),
    vccrypt_buffer_t* UNUSED(d))
{
    return -1;
}

/**
 * \brief Dummy contract resolver for parser options.
 */
static int dummy_contract_resolver(
    void* UNUSED(a), void* UNUSED(b), const uint8_t* UNUSED(c),
    const uint8_t* UNUSED(d), vccert_contract_closure_t* UNUSED(e))
{
    return -1;
}

/**
 * \brief Dummy key resolver for parser options.
 */
static bool dummy_key_resolver(
    void* UNUSED(a), void* UNUSED(b), uint64_t UNUSED(c),
    const uint8_t* UNUSED(d), vccrypt_buffer_t* UNUSED(e),
    vccrypt_buffer_t* UNUSED(f))
{
    return false;
}

/**
 * \brief Release the private entity certificate resource.
 */
static status vcblockchain_entity_private_cert_resource_release(resource* r)
{
    vcblockchain_entity_private_cert* cert =
        (vcblockchain_entity_private_cert*)r;

    /* cache the allocator. */
    allocator_options_t* alloc_opts = cert->pub.alloc_opts;

    /* dispose all buffers. */
    dispose((disposable_t*)&cert->pub.public_encryption_key);
    dispose((disposable_t*)&cert->pub.public_signing_key);
    dispose((disposable_t*)&cert->private_encryption_key);
    dispose((disposable_t*)&cert->private_signing_key);

    /* clear the structure. */
    memset(cert, 0, sizeof(*cert));

    /* release the structure. */
    release(alloc_opts, cert);

    /* success. */
    return STATUS_SUCCESS;
}
