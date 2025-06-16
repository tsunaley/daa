#include "inc/common.h"
#include "inc/verifier.h"
/*
 * verifier验证证书
 */
int verify(pairing_t pairing, element_t R, element_t S, element_t T, element_t W, element_t X, element_t Y, element_t P2, unsigned char *signatureS, unsigned char *hash_res, unsigned char *signatureR, char *k){
    element_t t1, t2, t3;
    element_init_GT(t1, pairing);
    element_init_GT(t2, pairing);
    element_init_G1(t3, pairing);

    // e(R, Y) =? e(S, P2)
    pairing_apply(t1, R, Y, pairing);
    pairing_apply(t2, S, P2, pairing);
    if(element_cmp(t1, t2)){
        cout<<"check cred fail";
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);

        return 0;
    }
    // e(R+W, X) =? e(T, P2)
    element_add(t3, R, W);
    pairing_apply(t1, t3, X, pairing);
    pairing_apply(t2, T, P2, pairing);
    if(element_cmp(t1, t2)){
        cout<<"check cred fail";
        element_clear(t1);
        element_clear(t2);
        element_clear(t3);

        return 0;
    }
    element_clear(t1);
    element_clear(t2);
    // element_clear(t3);

    unsigned char v[32];
    element_t sig, V, J2, L, E, K;
    SHA256_CTX h;
    mpz_t gmp_temp;

    SHA256_Init(&h);
    SHA256_Update(&h, signatureR, 32);
    SHA256_Update(&h, hash_res, 32);
    SHA256_Final(v, &h);

    char sss[300], str[2000];
    element_init_G1(J2, pairing);
    element_init_G1(K, pairing);
    element_init_G1(L, pairing);
    element_init_G1(E, pairing);
    element_init_Zr(sig, pairing);
    element_init_Zr(V, pairing);
    byte_to_char(signatureS, sss);
    
    mpz_init_set_str(gmp_temp, sss, 16);
    // element_set_str(sig, sss, 16);
    element_set_mpz(sig, gmp_temp);

    byte_to_char(v, sss);
    mpz_init_set_str(gmp_temp, sss, 16);
    // element_set_str(V, sss, 16);
    element_set_mpz(V, gmp_temp);
    element_set_str(K, k, 10);
    bsn_to_element(&J2);

    // L' = [s]J - [v]K
    element_pow_zn(L, J2, sig);
    element_pow_zn(t3, K, V);
    element_sub(L, L, t3);

    // E' = [s]S - [v]W
    element_pow_zn(E, S, sig);
    element_pow_zn(t3, W, V);
    element_sub(E, E, t3);

    element_snprint(sss, 256, R);
    strcpy(str, sss);
    element_snprint(sss, 256, S);
    strcat(str, sss);
    element_snprint(sss, 256, T);
    strcat(str, sss);
    element_snprint(sss, 256, W);
    strcat(str, sss);
    strcat(str, "2");

    // 相同的方式生成hash值并比较
    SHA256((unsigned char*)str, strlen(str), v);
    byte_to_char(v, sss);

    strcpy(str, sss);
    char msg[] = "1234567";
    strcat(str, msg);
    element_snprint(sss, 256, K);
    strcat(str, sss);
    // cout<<"K: "<<sss<<endl;
    element_snprint(sss, 256, L);
    strcat(str, sss);
    // cout<<"L: "<<sss<<endl;
    element_snprint(sss, 256, E);
    strcat(str, sss);
    // cout<<"E: "<<sss<<endl;
    strcat(str, J);
    strcat(str, "3");

    // cout << str << endl;
    // cout<<str<<endl;
    element_clear(t3);
    element_clear(sig);
    element_clear(V);
    element_clear(J2);
    element_clear(L);
    element_clear(E);
    element_clear(K);
    mpz_clear(gmp_temp);

    SHA256((unsigned char*)str, strlen(str), v);
    return memcmp(v, hash_res, 32);


}