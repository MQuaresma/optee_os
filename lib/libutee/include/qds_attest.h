#ifndef __PTA_ATTEST_UUID
#define __PTA_ATTEST_UUID

#define PTA_ATTEST_UUID {0x24391e36, 0xb2e9, 0x4278, \
                         {0xb7, 0xc3, 0x3b, 0xa0, 0xdf, 0x88, 0xa2, 0x3e}}

#define PTA_NAME "qds_attester.pta"

#define ATTEST_CMD_SIGN 1

struct attest_ctx{
    struct ecc_keypair *kp;
};

TEE_Result import_attestation_key(unsigned long kb);

#endif
