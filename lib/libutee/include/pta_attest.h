// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2020, Miguel Quaresma

/*
 * Attest (sign) data that has been generated inside the TEE
 */
#ifndef __PTA_ATTEST_UUID
#define __PTA_ATTEST_UUID

#define PTA_ATTEST_UUID {0x24391e36, 0xb2e9, 0x4278, \
                         {0xb7, 0xc3, 0x3b, 0xa0, 0xdf, 0x88, 0xa2, 0x3e}}

#define PTA_NAME "attester.pta"

/*
 * Sign(attest) a buffer of data
 *
 * [in]     memref[0]       Data to be signed
 * [out]    memref[1]       Signature
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_OUT_OF_MEMORY - Insufficient memory for allocation
 *
 */
#define ATTEST_CMD_SIGN 1

/*
 * Get the device certificate
 *
 * [out]    memref[1]       Device certificate
 *
 * Return codes:
 * TEE_SUCCESS - Invoke command success
 * TEE_ERROR_BAD_PARAMETERS - Incorrect input param
 * TEE_ERROR_ITEM_NOT_FOUND - Certificate not found in Trusted Storage
 * TEE_ERROR_CORRUPT_OBJECT - Certificate corrupt
 */
#define ATTEST_CMD_GET_CERT 2

struct attest_ctx{
    struct ecc_keypair *kp;
	void *dc;
	size_t dc_l;
};

TEE_Result import_attestation_key(void *dcak_p, size_t dc_l, size_t ak_l);

#endif
