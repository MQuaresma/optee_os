// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2020, Miguel Quaresma
void *cert_alloc_and_copy(void *cert, size_t cert_size);

/*
 * Verifies the certificate signature, using the internal RSA key
 *
 * Returns TEE_SUCCESS or TEE_ERROR_SECURITY
 */
TEE_Result verify_cert(void *cert);
