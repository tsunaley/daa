
#include <iostream>
#include <cstring>
#include <tss2/tss2_esys.h>
#include <gmp.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>

#define J "test" // 基础名称
using namespace std;

extern pairing_t pairing;
extern element_t P1, P2, Q1, x, y, X, Y, A, B, C, D;

// 公共工具函数
void ECC_point_to_str(TPM2B_ECC_POINT *P, char *s);
void h2(const char *m, TPM2B_SENSITIVE_DATA *s, TPM2B_ECC_PARAMETER *y);
void bsn_to_point(const char *m2, char *s2, char *x2, char *y2);
void byte_to_char(unsigned char *md, char *s, int size=32);
void char_to_byte(char *s, BYTE *bytes);
void element_to_ECCPoint(element_t e, TPM2B_ECC_POINT *P1);
void bsn_to_element(element_t *J2);
void init_pairing_and_elements();