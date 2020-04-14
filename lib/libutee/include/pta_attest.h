#ifndef __PTA_ATTEST_UUID
#define __PTA_ATTEST_UUID

#define PTA_ATTEST_UUID {0x24391e36, 0xb2e9, 0x4278, \
                         {0xb7, 0xc3, 0x3b, 0xa0, 0xdf, 0x88, 0xa2, 0x3e}}

#define PTA_NAME "attester.pta"

#define ATTEST_CMD_SIGN 1
#define ATTEST_CMD_GET_CERT 2

struct attest_ctx{
    struct ecc_keypair *kp;
	void *dc;
	size_t dc_l;
};

TEE_Result import_attestation_key(void *dcak_p, size_t dc_l, size_t ak_l);

#endif
