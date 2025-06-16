#include "inc/common.h"
#include "inc/issuer.h"

/*
 * issuer生成证书ABCD
 */
void issuer_make_cred(pairing_t pairing, element_t P1, element_t Q1, element_t *A, element_t *B, element_t *C, element_t *D, element_t x, element_t y){
    element_t temp, r;

    element_init_Zr(r, pairing);
    element_init_Zr(temp, pairing);

    element_random(r);

    element_pow_zn(*A, P1, r);  // A = [r]P1

    element_pow_zn(*C, *A, x);
    element_mul(temp, r, x);
    element_mul(temp, temp, y);
    element_pow_zn(*B, Q1, temp);
    element_add(*C, *C, *B);  // C = [x]A + [rxy]Q
    element_mul(temp, r, y);
    element_pow_zn(*D, Q1, temp);  // D = [ry]Q

    element_pow_zn(*B, *A, y);  // B = [y]A


    element_clear(r);
    element_clear(temp);
}

/*
 * issuer生成公私钥
 */
void create_issuer_key(pairing_t pairing, element_t *x, element_t *y, element_t *X, element_t *Y, element_t P1, element_t P2)
{   element_random(*x);
    element_random(*y);

    element_pow_zn(*X, P2, *x);
    element_pow_zn(*Y, P2, *y);
}