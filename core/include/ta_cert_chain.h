// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2020, Miguel Quaresma
#include<signed_hdr.h>

void *cert_alloc_and_copy(void *cert, size_t cert_size);

/*
 * Verifies the certificate signature, using the internal RSA key
 *
 * Returns TEE_SUCCESS or TEE_ERROR_SECURITY
 */
TEE_Result verify_cert(void *payload, size_t len, size_t sig_size, uint32_t algo);


/*
 * Extracts a public key from a buffer of raw bytes
 *
 * Returns TEE_SUCCESS, TEE_ERROR_OUT_OF_MEMORY or TEE_ERROR_BAD_FORMAT
 */
TEE_Result extract_key(struct shdr_thirdparty_ta *shdr_ta, size_t sig_size, void *cert_raw, void **dst);
