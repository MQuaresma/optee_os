// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2020, Miguel Quaresma
#include<io.h>
#include<crypto/crypto.h>
#include<stdlib.h>
#include<ta_pub_key.h>
#include<ta_cert_chain.h>
#include<signed_hdr.h>
#include<string.h>


void *cert_alloc_and_copy(void *cert, size_t cert_size){
    void *sec_cert = NULL;

    sec_cert = calloc(cert_size, 1);
    if(!sec_cert)
        return NULL;

    memcpy(sec_cert, cert, cert_size);

    return sec_cert;
}


TEE_Result verify_cert(void *payload, size_t len, size_t sig_size, uint32_t algo){
    TEE_Result res;
    struct rsa_public_key key;
    void *sig = payload, *pub_key = (uint8_t*)payload + sig_size, *md_ctx, *md;
    size_t md_len;
    uint32_t e = TEE_U32_TO_BIG_ENDIAN(ta_pub_key_exponent);

    res = crypto_hash_alloc_ctx(&md_ctx, TEE_DIGEST_HASH_TO_ALGO(algo));
    if(res)
        goto out;

    res = crypto_hash_init(md_ctx);
    if(res)
        goto error_free_hash_ctx;

    crypto_hash_update(md_ctx, (uint8_t *)pub_key, len-sig_size);
    if(res)
        goto error_free_hash_ctx;

    md_len = TEE_ALG_GET_DIGEST_SIZE(TEE_DIGEST_HASH_TO_ALGO(algo));
    md = calloc(md_len, 1);
    if(!md)
        goto error_free_md;

    res = crypto_hash_final(md_ctx, md, md_len);
    if(res)
        goto error_free_md;

    res = crypto_acipher_alloc_rsa_public_key(&key, sig_size);
    if(res)
        goto error_free_md;

    res = crypto_bignum_bin2bn((uint8_t *)&e, sizeof(e), key.e);
    if(res)
        goto error_free_rsa_ctx;

    res = crypto_bignum_bin2bn(ta_pub_key_modulus, ta_pub_key_modulus_size, key.n);
    if(res)
        goto error_free_rsa_ctx;

    res = crypto_acipher_rsassa_verify(algo, &key, md_len,
                                       md, md_len,
                                       sig, sig_size);

error_free_rsa_ctx:
    crypto_acipher_free_rsa_public_key(&key);
error_free_md:
    free(md);
error_free_hash_ctx:
    crypto_hash_free_ctx(md_ctx);
out:
    return (res ? TEE_ERROR_SECURITY : TEE_SUCCESS);
}


TEE_Result extract_key(struct shdr_thirdparty_ta *shdr_ta, size_t sig_size, void *raw_key, void *key){
    TEE_Result res;
    struct rsa_public_key *key_p = (struct rsa_public_key *)key;

    res = crypto_acipher_alloc_rsa_public_key(key_p, sig_size);
    if(res)
        return TEE_ERROR_SECURITY;

    raw_key = (uint8_t *)raw_key + sig_size;

    res = crypto_bignum_bin2bn((uint8_t *)raw_key, sizeof(ta_pub_key_exponent), key_p->e);
    if (res)
        goto out;

    raw_key = (uint8_t *)raw_key + sizeof(ta_pub_key_exponent);

    res = crypto_bignum_bin2bn((uint8_t *)raw_key, shdr_ta->key_info.ta_pub_key_modulus_size, key_p->n);
out:
    return (res ? TEE_ERROR_SECURITY : TEE_SUCCESS);
}
