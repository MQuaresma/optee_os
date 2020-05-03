// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2020, Miguel Quaresma

#include<crypto/crypto.h>
#include<ta_pub_key.h>


void *crt_alloc_and_copy(){

}

TEE_Result verify_cert(){
    struct ras_public_key key;
    TEE_Result res;
    uint32_t e = TEE_U32_TO_BIG_ENDIAN(ta_pub_key_exponent);

    res = crypto_acipher_alloc_rsa_public_key(&key, ta_pub_key_modulus_size);
    if(res)
        return TEE_ERROR_SECURITY;

    res = crypto_bignum_bin2bn((uint8_t *)&e, sizeof(e), key.e);
    if(res)
        goto out;

    res = crypto_bignum_bin2bn((uint8_t *)ta_pub_key_modulus, ta_pub_key_modulus_size, key.n);
    if(res)
        goto out;

    res = crypto_acipher_rsassa_verify();

out:
    crypto_acipher_free_rsa_public_key(&key);
    return (res ? TEE_ERROR_SECURITY : TEE_SUCCESS);
}
