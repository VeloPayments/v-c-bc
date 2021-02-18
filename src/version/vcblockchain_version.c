/**
 * \file version/vcblockchain_version.c
 *
 * \brief Return the version string for the vcblockchain library.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#include <config.h>
#include <vcblockchain/version.h>

/**
 * \brief Return the version string for the vcblockchain library.
 *
 * \returns a const version string for this library.
 */
const char* vcblockchain_version()
{
    return VCBLOCKCHAIN_VERSION;
}
