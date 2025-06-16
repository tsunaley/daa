#include "inc/common.h"
#include "inc/issuer.h"
#include "inc/prover.h"
#include "inc/verifier.h"

int main() {
    // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 颁发证书 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    // 公共参数初始化

    init_pairing_and_elements();
    int ret;
    char sss[500]="";
    char str[2000] = "";
    char str0[1000] = "";
    unsigned char hash_res[32], signatureS[32], signatureR[32];



    /*********************************************************************************** 
    *** prover调用TPM 首先初始化TPM相关参数，然后生成私钥sk，并计算Q = [sk]P1（P1是基点）***
    ************************************************************************************/
    TSS2_RC rc;
    ESYS_CONTEXT *esys_context = NULL;
    ESYS_TR eccHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPM2B_PUBLIC *pubkey = NULL;

    rc = tpm_generate_ecc_key(&esys_context, &eccHandle, &session, &pubkey);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "ECC key generation failed: 0x%X\n", rc);
        return 1;
    }

    TPM2B_ECC_POINT Q;
    Q.point = pubkey->publicArea.unique.ecc;
    ECC_point_to_str(&Q, sss);
    strcat(str, sss);
    element_set_str(Q1, sss, 10);



    /*********************************************************************************** 
    ***                      issuer生成公私钥对 接收Q并生成证明                        ***
    ************************************************************************************/
    create_issuer_key(pairing, &x, &y, &X, &Y, P1, P2);

    issuer_make_cred(pairing, P1, Q1, &A, &B, &C, &D, x, y);
    element_snprint(sss, 256, A);
    cout<<"A: "<<sss<<endl;
    element_snprint(sss, 256, B);
    cout<<"B: "<<sss<<endl;
    element_snprint(sss, 256, C);
    cout<<"C: "<<sss<<endl;
    element_snprint(sss, 256, D);
    cout<<"D: "<<sss<<endl;



    /*********************************************************************************** 
    ***                           证书ABCD交给prover检查                              ***
    ************************************************************************************/
    ret = check_cred(pairing, P1, P2, A, B, C, D, X, Y);
    if(ret!=1){
        return 0;
    }
    cout<<"check credential success"<<endl;




    // >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> 签名与验证 <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    /*********************************************************************************** 
    ***                       prover随机化证书生成新的证书RSTW                         ***
    ************************************************************************************/
    element_t R, S, T, W;
    element_init_G1(R, pairing);
    element_init_G1(S, pairing);
    element_init_G1(T, pairing);
    element_init_G1(W, pairing);
    rand_cred(pairing, A, B, C, D, &R, &S, &T, &W);



    /*********************************************************************************** 
    ***                                 prover签名                                   ***
    ************************************************************************************/
    TPM2B_ECC_POINT ecc_S;
    element_to_ECCPoint(S, &ecc_S);
    ecc_S.point.x.size = 32;
    ecc_S.point.y.size = 32;
    TPM2B_ECC_POINT *K = NULL;
    TPM2B_ECC_POINT *L = NULL;
    TPM2B_ECC_POINT *E = NULL;
    UINT16 counter;
    commit(esys_context, &ecc_S, &K, &L, &E, J, &counter, &eccHandle, &session, 1);

    // 初始化sign函数相关的参数
    TPM2B_DIGEST digest;
    memcpy(digest.buffer, hash_res, 32);
    digest.size = 32;

    TPMT_SIG_SCHEME inScheme;
    inScheme.scheme = TPM2_ALG_ECDAA;
	inScheme.details.ecdaa.hashAlg = TPM2_ALG_SHA256;
	inScheme.details.ecdaa.count = counter;
    

    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_OWNER,
        .digest = {0}
    };
    TPMT_SIGNATURE *signature = NULL;


    // 将相关的值、msg等进行拼接字符串并计算hash
    element_snprint(sss, 256, R);
    cout<<"R: "<<sss<<endl;
    strcpy(str, sss);
    element_snprint(sss, 256, S);
    cout<<"S: "<<sss<<endl;
    strcat(str, sss);
    element_snprint(sss, 256, T);
    cout<<"T: "<<sss<<endl;
    strcat(str, sss);
    element_snprint(sss, 256, W);
    cout<<"W: "<<sss<<endl;
    strcat(str, sss);
    strcat(str, "2");
    SHA256((unsigned char*)str, strlen(str), hash_res);
    byte_to_char(hash_res, str0, 32);
    strcpy(str, str0);
    char msg[] = "1234567";  // 要发送的消息默认写成1234567了 根据情况更改
    strcat(str, msg);
    ECC_point_to_str(K, sss);
    strcat(str, sss);
    cout<<"K: "<<sss<<endl;
    ECC_point_to_str(L, sss);
    strcat(str, sss);
    cout<<"L: "<<sss<<endl;
    ECC_point_to_str(E, sss);
    strcat(str, sss);
    cout<<"E: "<<sss<<endl;
    strcat(str, J);
    strcat(str, "3");

    SHA256((unsigned char*)str, strlen(str), hash_res);
    memcpy(digest.buffer, hash_res, 32);
    // cout << str << endl;
    inScheme.details.ecdaa.count = counter;
    // 签名
    Esys_Sign(esys_context, eccHandle, session, ESYS_TR_NONE, ESYS_TR_NONE, &digest, &inScheme, &hash_validation, &signature);
    memcpy(signatureR, signature->signature.ecdaa.signatureR.buffer, 32);
    memcpy(signatureS, signature->signature.ecdaa.signatureS.buffer, 32);
    ECC_point_to_str(K, sss);



    
    /*********************************************************************************** 
    ***   将R、S、T、W、J、K、hash值、签名s、msg、新鲜值等传递给verifier验证             ***
    ************************************************************************************/
    ret = verify(pairing, R, S, T, W, X, Y, P2, signatureS, hash_res, signatureR, sss);
    if(ret){
        cout<<"error"<<endl;
        return 0;
    }
    cout<<"check success"<<endl;
    return 0;
}
