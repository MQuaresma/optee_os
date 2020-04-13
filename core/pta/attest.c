// SPDX-License-Identifier: GPL-2.0-or-later
#include<crypto/crypto.h>
#include<kernel/pseudo_ta.h>
#include<kernel/user_ta.h>
#include<tee/tee_fs.h>
#include<tee/tee_svc_storage.h>
#include<tee/tee_svc_cryp.h>
#include<tee/tee_pobj.h>
#include<tee/tee_obj.h>
#include<tee_api_defines.h>
#include<stdbool.h>
#include<pta_attest.h>


/* Signs a binary blob corresponding to the byte representation of a CSR
 */
static TEE_Result sign_cert_blob(struct attest_ctx *ctx, uint32_t pt, TEE_Param params[4]){
    void *hash_ctx, *hash_tmp;
    
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
    
    
    if(crypto_acipher_ecc_sign(TEE_ALG_ECDSA_P256, ctx->kp, hash_tmp, 32,
                               params[1].memref.buffer, &(params[1].memref.size)))
        return TEE_ERROR_GENERIC;

    free(hash_tmp);

    return TEE_SUCCESS;
}

static void free_ecc_keypair(struct ecc_keypair *kp){
    free(kp->d);
    free(kp->x);
    free(kp->y);
    free(kp);
}


static void close_session(void *psess_ctx){
    struct ecc_keypair *kp = ((struct attest_ctx*)psess_ctx)->kp;
    free_ecc_keypair(kp);
    free(psess_ctx);
}


/* Loads signing key, used in attestation, from secure storage
 */
static TEE_Result load_attest_material(struct ecc_keypair **kpp){
    TEE_Result res = TEE_SUCCESS;
    TEE_UUID uuid = PTA_ATTEST_UUID;
    const struct tee_file_operations *fops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
    struct tee_file_handle *fh = NULL;
    struct tee_pobj *kp_pobj;
    struct tee_obj *kp_obj = tee_obj_alloc();
    void *buf = NULL;
    size_t buf_len = 1;

    if(kp_obj){
        res = tee_pobj_get(&uuid,
                           &uuid, sizeof(TEE_UUID),
                           TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_READ,
                           false, fops,
                           &kp_pobj);

        if(!res){
            if(!(res = fops->open(kp_pobj, &buf_len, &fh))){
                buf = calloc(buf_len, sizeof(uint8_t));
                if(buf){
                    res = fops->read(fh, 0, buf, &buf_len);
                    if(!res){
                        kp_obj->info.objectType = TEE_TYPE_ECDSA_KEYPAIR;
                        kp_obj->attr = calloc(1, sizeof(struct ecc_keypair));

                        if(!kp_obj->attr || crypto_acipher_alloc_ecc_keypair(kp_obj->attr, 256))
                            res = TEE_ERROR_OUT_OF_MEMORY;
                        else if (!(res = tee_obj_attr_from_binary(kp_obj, buf, buf_len))){
                            *kpp = kp_obj->attr;
                            (*kpp)->curve = TEE_ECC_CURVE_NIST_P256;
                        }
                    }
                    free(buf);
                } else res = TEE_ERROR_OUT_OF_MEMORY;
                fops->close(&fh);
            }
            tee_pobj_release(kp_pobj);
        }

        kp_obj->attr = NULL;
        tee_obj_free(kp_obj);
    }
    return res;
}


static TEE_Result open_session(uint32_t pt __unused, TEE_Param params[TEE_NUM_PARAMS] __unused, void **psess_ctx){
    TEE_Result res = TEE_SUCCESS;
    struct tee_ta_session *s = tee_ta_get_calling_session();
    struct attest_ctx *ac;

    if(!s || !is_user_ta_ctx(s->ctx))
        return TEE_ERROR_ACCESS_DENIED;

    ac = calloc(1, sizeof(struct attest_ctx));
    if(!ac)
        return TEE_ERROR_OUT_OF_MEMORY;

    res = load_attest_material(&(ac->kp));

    if(res)
        return TEE_ERROR_CORRUPT_OBJECT;

    *psess_ctx = ac;
    
    return res;
}


/* Stores, in secure storage, a pointer to the ECDSA keypair generated at startup
 */
static TEE_Result store_attest_material(void *kpp_raw, struct tee_pobj *kp_pobj, struct tee_file_handle **fh, const struct tee_file_operations *fops){
    TEE_Result res = TEE_SUCCESS;
    struct ecc_keypair *kp = (struct ecc_keypair*)kpp_raw;
    struct tee_obj *tmp_obj = tee_obj_alloc();
    void *buf;
    size_t buf_len;

    if(tmp_obj){
        tmp_obj->attr = kp;
        tmp_obj->info.objectType = TEE_TYPE_ECDSA_KEYPAIR;

        buf_len = crypto_bignum_num_bytes(kp->d) +  crypto_bignum_num_bytes(kp->x) +  crypto_bignum_num_bytes(kp->y) +  sizeof(kp->curve);
        buf = calloc(buf_len, sizeof(uint8_t));

        if(buf){
            res = tee_obj_attr_to_binary(tmp_obj, buf, &buf_len);

            res = fops->create(kp_pobj, true, NULL, 0, NULL, 0, buf, buf_len, fh);

            free(buf);
        }else res = TEE_ERROR_OUT_OF_MEMORY;

        tmp_obj->attr = NULL;
        tee_obj_free(tmp_obj);
    } else res = TEE_ERROR_OUT_OF_MEMORY;

    return res;
}

TEE_Result import_attestation_key(void *dc, size_t dc_size){
	//TODO: store certificate in secure storage once session point
	//is created and extract signing key
	return TEE_SUCCESS;
}

/* Loads ECDSA keypair from x509 device certificate loaded at boot time
 */
static TEE_Result create(void){
    TEE_Result res = TEE_SUCCESS;
    TEE_UUID uuid = PTA_ATTEST_UUID;
    const struct tee_file_operations *fops = tee_svc_storage_file_ops(TEE_STORAGE_PRIVATE);
    struct tee_file_handle *fh = NULL;
    struct tee_pobj *kp_pobj = NULL;
    struct ecc_keypair *kp = NULL;
    size_t obj_size = sizeof(void*);

    res = tee_pobj_get(&uuid,
                       &uuid, sizeof(TEE_UUID),
                       TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_READ,
                       false, fops,
                       &kp_pobj);
    if(!res){
        res = fops->open(kp_pobj, &obj_size, &fh);

        if(!(res ^ TEE_ERROR_ITEM_NOT_FOUND) || !(res ^ TEE_ERROR_CORRUPT_OBJECT)){
            /* Generate attestation key */
            if(!(kp = calloc(1, sizeof(struct ecc_keypair))))
                return TEE_ERROR_OUT_OF_MEMORY;

            if(crypto_acipher_alloc_ecc_keypair(kp, 256)) 
                return TEE_ERROR_OUT_OF_MEMORY;

            kp->curve = TEE_ECC_CURVE_NIST_P256;

            if(crypto_acipher_gen_ecc_key(kp))
                return TEE_ERROR_GENERIC;

            res = store_attest_material(kp, kp_pobj, &fh, fops);
            free_ecc_keypair(kp);
        }

        fops->close(&fh);
        tee_pobj_release(kp_pobj);
    }
    
    return res;
}


static TEE_Result invoke_command(void *psess, uint32_t cmd, uint32_t pt, TEE_Param params[4]){

    switch(cmd){
    case ATTEST_CMD_SIGN:
        return sign_cert_blob(psess, pt, params);
    default:
        break;
    }

    return TEE_ERROR_NOT_IMPLEMENTED;
}

pseudo_ta_register(.uuid = PTA_ATTEST_UUID, .name = PTA_NAME,
                   .flags = PTA_DEFAULT_FLAGS,
                   .create_entry_point = create,
                   .open_session_entry_point = open_session,
                   .close_session_entry_point = close_session,
                   .invoke_command_entry_point = invoke_command);
