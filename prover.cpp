#include "inc/common.h"
#include "inc/prover.h"

TSS2_RC tpm_generate_ecc_key(ESYS_CONTEXT **ctx_out,
                              ESYS_TR *key_handle_out,
                              ESYS_TR *session_out,
                              TPM2B_PUBLIC **pubkey_out) {
    TSS2_RC r;
    ESYS_CONTEXT *esys_context = NULL;
    ESYS_TR session = ESYS_TR_NONE;
    ESYS_TR eccHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    r = Esys_Initialize(&esys_context, NULL, NULL);
    if (r != TSS2_RC_SUCCESS) return r;

    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                   11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = { .aes = 128 },
        .mode = {.aes = TPM2_ALG_CFB}
    };


    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {.size = 0},
            .data = {.size = 0}
        }
    };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters = {
                .eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                     .keyBits = {.aes = 128},
                     .mode = {.aes = TPM2_ALG_CFB},
                 },
                 .scheme = {
                      .scheme = TPM2_ALG_ECDAA,
                      .details = {.ecdaa = {.hashAlg = TPM2_ALG_SHA256, .count = 1}
                      }
                  },
                 .curveID = TPM2_ECC_BN_P256,
                 .kdf = {.scheme = TPM2_ALG_NULL }
                }
             },
             .unique = {
                .ecc = {
                    .x = {.size = 32,.buffer = {0}},
                    .y = {.size = 32,.buffer = {0}}
                }
             },
        }
    };

    TPM2B_DATA outsideInfo = {.size = 0};
    TPML_PCR_SELECTION creationPCR = {.count = 0};

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
                              &session);
    if (r != TSS2_RC_SUCCESS) goto cleanup;

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, session,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive,
                           &inPublic, &outsideInfo, &creationPCR,
                           &eccHandle, &outPublic, &creationData,
                           &creationHash, &creationTicket);
    if (r != TSS2_RC_SUCCESS) goto cleanup;

    *ctx_out = esys_context;
    *key_handle_out = eccHandle;
    *session_out = session;
    *pubkey_out = outPublic;
    // caller is responsible for flushing/freeing

    return TSS2_RC_SUCCESS;

cleanup:
    if (session != ESYS_TR_NONE) Esys_FlushContext(esys_context, session);
    if (eccHandle != ESYS_TR_NONE) Esys_FlushContext(esys_context, eccHandle);
    if (esys_context) Esys_Finalize(&esys_context);
    return r;
}


/*
 * 对tpm的commit函数进行了简单的包装
 */
void commit(ESYS_CONTEXT *esys_context, TPM2B_ECC_POINT *P1, TPM2B_ECC_POINT **K, TPM2B_ECC_POINT **L, TPM2B_ECC_POINT **E, const char *j, UINT16 *counter, ESYS_TR *eccHandle, ESYS_TR *session, int flag){
    TSS2_RC r;
    TPM2B_SENSITIVE_DATA s2={0};
    TPM2B_ECC_PARAMETER y2={0};

    if(flag==1) h2(j, &s2, &y2);
    r = Esys_Commit(esys_context, *eccHandle,
                    *session, ESYS_TR_NONE, ESYS_TR_NONE,
                    P1, &s2, &y2,
                    K, L, E, counter);
}


/*
 * prover验证收到的证书是否有效
 */
int check_cred(pairing_t pairing, element_t P1, element_t P2, element_t A, element_t B, element_t C, element_t D, element_t X, element_t Y){
    element_t t1, t2, t3;
    
    element_init_GT(t1, pairing);
    element_init_GT(t2, pairing);
    element_init_G1(t3, pairing);

    // e(A, Y) =? e(B, P2)
    pairing_apply(t1, A, Y, pairing);
    pairing_apply(t2, B, P2, pairing);

    if(element_cmp(t1, t2)){
        cout<<"check cred fail";
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);

        return 0;
    }

    // e(A+D, X) =? e(C, P2)
    element_add(t3, A, D);
    pairing_apply(t1, t3, X, pairing);
    pairing_apply(t2, C, P2, pairing);

    if(element_cmp(t1, t2)){
        cout<<"check cred fail";
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);
        return 0;
    }
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);
    return 1;
}

/*
 * prover随机化证书
 */
void rand_cred(pairing_t pairing, element_t A, element_t B, element_t C, element_t D, element_t *R, element_t *S, element_t *T, element_t *W){
    element_t l;
    char sss[300];
    element_init_Zr(l, pairing);
    element_random(l);
    element_pow_zn(*R, A, l);
    element_pow_zn(*S, B, l);
    element_pow_zn(*T, C, l);
    element_pow_zn(*W, D, l);
}