
TSS2_RC tpm_generate_ecc_key(ESYS_CONTEXT **ctx_out, ESYS_TR *key_handle_out, ESYS_TR *session_out, TPM2B_PUBLIC **pubkey_out);
void commit(ESYS_CONTEXT *esys_context, TPM2B_ECC_POINT *P1, TPM2B_ECC_POINT **K, TPM2B_ECC_POINT **L, TPM2B_ECC_POINT **E, const char *j, UINT16 *counter, ESYS_TR *eccHandle, ESYS_TR *session, int flag);
int check_cred(pairing_t pairing, element_t P1, element_t P2, element_t A, element_t B, element_t C, element_t D, element_t X, element_t Y);
void rand_cred(pairing_t pairing, element_t A, element_t B, element_t C, element_t D, element_t *R, element_t *S, element_t *T, element_t *W);