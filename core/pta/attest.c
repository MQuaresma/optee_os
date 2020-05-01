// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2020, Miguel Quaresma
#include<crypto/crypto.h>
#include<kernel/huk_subkey.h>
#include<kernel/pseudo_ta.h>
#include<kernel/user_ta.h>
#include<tee/tee_fs.h>
#include<tee/tee_svc_storage.h>
#include<tee/tee_svc_cryp.h>
#include<tee/tee_pobj.h>
#include<tee/tee_obj.h>
#include<tee_api_defines.h>
#include<stdbool.h>
#include<string.h>
#include<pta_attest.h>

static struct attest_ctx ctx_i;

/* Signs a binary blob corresponding to the byte representation of a CSR
 */
static TEE_Result sign_blob(uint32_t pt, TEE_Param params[4]){
    void *hash_ctx = NULL, *hash_tmp = NULL;
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, //cert blob
                                    TEE_PARAM_TYPE_MEMREF_OUTPUT, //signature
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);

    if(e_pt != pt)
        return TEE_ERROR_BAD_PARAMETERS;

    if(crypto_hash_alloc_ctx(&hash_ctx, TEE_ALG_SHA256) || crypto_hash_init(hash_ctx))
        return TEE_ERROR_GENERIC;

    hash_tmp = calloc(32, sizeof(uint8_t));

    if(crypto_hash_update(hash_ctx, params[0].memref.buffer, params[0].memref.size) ||
       crypto_hash_final(hash_ctx, hash_tmp, 32))
        return TEE_ERROR_GENERIC;

    crypto_hash_free_ctx(hash_ctx);

    if(crypto_acipher_ecc_sign_asn(TEE_ALG_ECDSA_P256, ctx_i.kp,
                                   TEE_ALG_SHA256,
                                   hash_tmp, 32,
                                   params[1].memref.buffer, &(params[1].memref.size)))
        return TEE_ERROR_GENERIC;

    free(hash_tmp);

    return TEE_SUCCESS;
}


/* Dumps the device certificate in a buffer
 */
static TEE_Result dump_dc(uint32_t pt, TEE_Param params[4]){
    TEE_Result res = TEE_SUCCESS;
    TEE_UUID uuid = PTA_ATTEST_UUID;
    const struct tee_file_operations *fops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
    struct tee_file_handle *fh = NULL;
    struct tee_pobj *dc_obj = NULL;
    size_t dc_objs = sizeof(void*);
    uint32_t e_pt = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);
    if(e_pt != pt)
        return TEE_ERROR_BAD_PARAMETERS;

    res = tee_pobj_get(&uuid,
                       &uuid, sizeof(TEE_UUID),
                       TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_READ,
                       false, fops,
                       &dc_obj);
    if(!res){
        res = fops->open(dc_obj, &dc_objs, &fh);
        if(!(res ^ TEE_ERROR_ITEM_NOT_FOUND) || !(res ^ TEE_ERROR_CORRUPT_OBJECT))
            return res;
        res = fops->read(fh, 0, params[0].memref.buffer, &params[0].memref.size);
        fops->close(&fh);
        tee_pobj_release(dc_obj);
    }

    return res;
}


static TEE_Result open_session(uint32_t pt __unused, TEE_Param params[TEE_NUM_PARAMS] __unused, void **psess_ctx){
    TEE_Result res = TEE_SUCCESS;
    struct tee_ta_session *s = tee_ta_get_calling_session();

    if(!s || !is_user_ta_ctx(s->ctx))
        return TEE_ERROR_ACCESS_DENIED;

    *psess_ctx = &ctx_i;
    
    return res;
}


/* Stores, in secure storage, the device certificate loaded at boot time
 */
static TEE_Result store_attest_material(struct tee_pobj *kp_pobj, 
                                        struct tee_file_handle **fh,
                                        const struct tee_file_operations *fops){
    TEE_Result res = TEE_SUCCESS;
    res = fops->create(kp_pobj, true, NULL, 0, NULL, 0, ctx_i.dc, ctx_i.dc_l, fh);
    if(!res){
        free(ctx_i.dc);
        ctx_i.dc = NULL;
        ctx_i.dc_l = 0;
    }

    return res;
}


/* Checks if the device certificate has been stored, and stores it in case it
 * hasn't
 */
static TEE_Result create(void){
    TEE_Result res = TEE_SUCCESS;
    TEE_UUID uuid = PTA_ATTEST_UUID;
    const struct tee_file_operations *fops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
    struct tee_file_handle *fh = NULL;
    struct tee_pobj *dc_obj = NULL;
    size_t dc_objs = sizeof(void*);

    res = tee_pobj_get(&uuid,
                       &uuid, sizeof(TEE_UUID),
                       TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_READ,
                       false, fops,
                       &dc_obj);
    if(!res){
        res = fops->open(dc_obj, &dc_objs, &fh);
        if(!(res ^ TEE_ERROR_ITEM_NOT_FOUND) || !(res ^ TEE_ERROR_CORRUPT_OBJECT))
            res = store_attest_material(dc_obj, &fh, fops);

        fops->close(&fh);
        tee_pobj_release(dc_obj);
    }

    return res;
}


static TEE_Result decrypt_ak(void *ak_blob, size_t ak_l){
    TEE_Result res = TEE_SUCCESS;
    void *ctx = NULL;
    uint8_t *key = NULL, *tmp = NULL;
    size_t b_len = 16;

    key = calloc(b_len, sizeof(uint8_t));
    if(!key)
        return TEE_ERROR_OUT_OF_MEMORY;

    tmp = calloc(ak_l, sizeof(uint8_t));
    if(tmp){
        res = huk_subkey_derive(HUK_SUBKEY_ACC, NULL, 0, key, b_len);

        if(!res){
            res = crypto_cipher_alloc_ctx(&ctx, TEE_ALG_AES_CTR);

            if(!res){
                res = crypto_cipher_init(ctx, TEE_MODE_DECRYPT, key, b_len, NULL, 0, tmp, b_len);

                if(!res){
                    res = crypto_cipher_update(ctx, TEE_MODE_DECRYPT, 1, (uint8_t*)ak_blob, ak_l, tmp);

                    if(!res){
                        memcpy((uint8_t*)ak_blob, tmp, ak_l);
                        memset(tmp, 0, ak_l*sizeof(uint8_t));
                    }
                    crypto_cipher_final(ctx);
                }
                crypto_cipher_free_ctx(ctx);
            }
            memset(key, 0, b_len*sizeof(uint8_t));
        }
        free(tmp);
    } else res = TEE_ERROR_OUT_OF_MEMORY;

    free(key);

    return res;
}


static inline TEE_Result bin_2_ecckey(uint8_t *blob, size_t ak_l){
    TEE_Result res = TEE_SUCCESS;
    size_t key_size = ak_l/3;

    res = decrypt_ak(blob, key_size);
    if(res)
        return res;

    ctx_i.kp = calloc(1, sizeof(struct ecc_keypair));
    if(!ctx_i.kp)
        return TEE_ERROR_OUT_OF_MEMORY;

    res = crypto_acipher_alloc_ecc_keypair(ctx_i.kp, 256);
    if(res)
        return res;

    res = crypto_bignum_bin2bn(blob, key_size, ctx_i.kp->d);
    if(res)
        return res;

    blob += key_size;
    res = crypto_bignum_bin2bn(blob, key_size, ctx_i.kp->x);
    if(res)
        return res;

    blob += key_size;
    res = crypto_bignum_bin2bn(blob, key_size, ctx_i.kp->y);
    if(res)
        return res;

    ctx_i.kp->curve = TEE_ECC_CURVE_NIST_P256;

    return res;
}


/* Loads the attestation blob i.e. device certificate followed by the attestation
 * key, encrypted using AES-CTR
 */
TEE_Result import_attestation_key(void *blob, size_t dc_l, size_t ak_l){
    TEE_Result res = TEE_SUCCESS;

    res = bin_2_ecckey((uint8_t *)blob + dc_l, ak_l);
    if(res)
        return res;

    ctx_i.dc = calloc(dc_l, sizeof(uint8_t));
    if(!ctx_i.dc)
        return TEE_ERROR_OUT_OF_MEMORY;

    memcpy(ctx_i.dc, blob, dc_l);
    ctx_i.dc_l = dc_l;

    return res;
}


static TEE_Result invoke_command(void *psess __unused, uint32_t cmd, uint32_t pt, TEE_Param params[4]){

    switch(cmd){
    case ATTEST_CMD_SIGN:
        return sign_blob(pt, params);
    case ATTEST_CMD_GET_CERT:
        return dump_dc(pt, params);
    default:
        break;
    }

    return TEE_ERROR_NOT_IMPLEMENTED;
}


pseudo_ta_register(.uuid = PTA_ATTEST_UUID, .name = PTA_NAME,
                   .flags = PTA_DEFAULT_FLAGS,
                   .create_entry_point = create,
                   .open_session_entry_point = open_session,
                   .invoke_command_entry_point = invoke_command);
