/**
 * \file vcblockchain/version.h
 *
 * \brief Return the version string for the vcblockchain library.
 *
 * \copyright 2021 Velo Payments, Inc.  All rights reserved.
 */

#ifndef  VCBLOCKCHAIN_VERSION_HEADER_GUARD
# define VCBLOCKCHAIN_VERSION_HEADER_GUARD

/* make this header C++ friendly. */
#ifdef   __cplusplus
extern "C" {
#endif /*__cplusplus*/

/**
 * \brief Return the version string for the vcblockchain library.
 *
 * \returns a const version string for this library.
 */
const char* vcblockchain_version();

/* make this header C++ friendly. */
#ifdef   __cplusplus
}
#endif /*__cplusplus*/

#endif /*VCBLOCKCHAIN_VERSION_HEADER_GUARD*/
