#include "inc/common.h"

/*
 * 用于将TPM生成的点转为[x, y]形式的字符串（十进制）
 */
void ECC_point_to_str(TPM2B_ECC_POINT *P, char *s) 
{
    mpz_t x, y, temp, h;
    mpz_init_set_si(h, 256);
    mpz_init_set_si(x, 0);
    mpz_init_set_si(y, 0);
    strcpy(s, "");

    char *str_temp;
    // cout<<'w'<<endl;

    for(int i = 0; i<32; i++){
        // cout<<int(P->point.x.buffer[i])<<endl;
        mpz_init_set_si(temp, int(P->point.x.buffer[i]));
        mpz_mul(x, x, h);
        mpz_add(x, x, temp);

        mpz_init_set_si(temp, int(P->point.y.buffer[i]));
        mpz_mul(y, y, h);
        mpz_add(y, y, temp);

    }
    strcat(s, "[");
    str_temp = mpz_get_str(NULL, 10, x);
    strcat(s, str_temp);
    strcat(s, ", ");

    mpz_get_str(str_temp, 10, y);
    strcat(s, str_temp);
    strcat(s, "]");
    // cout<<s<<endl;

    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(temp);
    mpz_clear(h);
}


/*
 * 将调用bsn_to_point函数生成的点转为commit函数要用到的TPM2B_SENSITIVE_DATA和TPM2B_ECC_PARAMETER格式
 */
void h2(const char *m2, TPM2B_SENSITIVE_DATA *s2, TPM2B_ECC_PARAMETER *y2){
    BYTE bytes[32];
    char s[300], x[300], y[300];
    bsn_to_point(m2, s, x, y);
    
    // cout<<y<<endl;
    // cout<<x<<endl;
    // cout<<s<<endl;

    char_to_byte(y, bytes);
    memcpy(y2->buffer, bytes, 32);
    y2->size = 32;
    s2->size = strlen(s);
    memcpy(s2->buffer, s, strlen(s));
}


/*
 * 将pbc的点格式转为TPM的点格式
 */
void element_to_ECCPoint(element_t e, TPM2B_ECC_POINT *P1){
    char sss[300], temp[300];
    mpz_t t;
    unsigned char bytes[32];
    element_snprint(sss, 256, e);
    // cout<<sss<<endl;
    int i=0;
    for(i=0;i<strlen(sss);i++){
        if(sss[i]==',') break;
    }
    // cout<<i<<endl;
    
    memcpy(temp, sss+1, i-1);
    temp[i-1] = '\0';
    // cout<<temp<<endl;
    mpz_init_set_str(t, temp, 10);
    mpz_get_str(temp, 16, t);
    // cout<<temp<<endl;
    char_to_byte(temp, bytes);
    memcpy(&P1->point.x.buffer, bytes, 32);

    memcpy(temp, sss+i+2, strlen(sss)-i-3);
    temp[strlen(sss)-i-3] = '\0';
    // cout<<temp<<endl;
    mpz_init_set_str(t, temp, 10);
    mpz_get_str(temp, 16, t);
    // cout<<temp<<endl;
    char_to_byte(temp, bytes);
    memcpy(&P1->point.y.buffer, bytes, 32);
}



/*
 * 将一个任意的字符串映射到椭圆曲线上的一点，利用到了二次剩余
 */
void bsn_to_point(const char *m2, char *s2, char *x2, char *y2)
{
    unsigned char temp[64];
    int result = -1;
    char *s;
    mpz_t x, q, right, y, temp1, temp2, i;
    mpz_init_set_str(q, "115792089237314936872688561244471742058375878355761205198700409522629664518163", 10);

    mpz_init_set_si(i, 0);
    mpz_init_set_si(temp1, 0);
    mpz_init_set_si(right, 0);
    mpz_init_set_si(temp2, 0);
    mpz_init_set_si(y, 0);

    do{
        s = mpz_get_str(NULL, 10, i);
        strcpy(s2, m2);
        strcat(s2, s);
        SHA256((unsigned char*)s2, strlen(s2), temp);
        byte_to_char(temp, x2, 32);
        mpz_init_set_str(x, x2, 16);
        mpz_powm_ui(temp1, x, 3, q);
        mpz_add_ui(right, temp1, 3);

        mpz_sub_ui(temp1, q, 1);
        mpz_cdiv_qr_ui(temp1, temp2, temp1, 2);
        if(mpz_cmp_si(temp2, 0)!=0) cout<<"(p-1)//2 error"<<endl;
        mpz_powm(temp1, right, temp1, q);
        
        result = mpz_cmp_si(temp1, 1);
        mpz_add_ui(i, i, 1);

    }while (result!=0);

    mpz_add_ui(temp1, q, 1);

    mpz_cdiv_qr_ui(temp1, temp2, temp1, 4);
    if(mpz_cmp_si(temp2, 0)!=0) cout<<"(p+1)//4 error"<<endl;
    mpz_powm(y, right, temp1, q);
    
    // cout<<"x: "<<x2<<endl;
    s = mpz_get_str(NULL, 16, y);
    strcpy(y2, s);
    // cout<<"y: "<<y2<<endl;
    
    mpz_clear(x);
    mpz_clear(q);
    mpz_clear(right);
    mpz_clear(y);
    mpz_clear(temp2);
    mpz_clear(temp1);
    mpz_clear(i);

}

/*
 * 将字节串转为十六进制字符串
 */
void byte_to_char(unsigned char *md, char *s, int size)
{
    char temp;
    for(int i=0;i<size;i++){
        temp = (md[i]&0xf0)>>4;
        if(temp>9) temp += 39;
        s[i*2] = temp+48;
        temp = md[i]&0x0f;
        if(temp>9) temp += 39;
        s[i*2+1] = temp+0x30;
    }
    s[size*2] = '\0';
}


/*
 * 将十六进制字符串转为字节串
 */
void char_to_byte(char *s, BYTE *bytes)
{
    int b = 0, t;
    BYTE temp1, temp2;
    for(int i=0;i<strlen(s);i+=2){
        temp1 = s[i]|32;
        temp2 = s[i+1]|32;

        temp1 = (temp1>='a'&temp1<='f')?temp1-39:temp1;
        temp2 = (temp2>='a'&temp2<='f')?temp2-39:temp2;

        bytes[b] = ((temp1&~0x30)<<4)|(temp2&~0x30);
        b++;
    }
}

/*
 * 将字符串转为pbc格式的点
 */
void bsn_to_element(element_t *J2){
    char s[300], x[300], y[300];
    mpz_t temp;
    bsn_to_point(J, s, x, y);
    strcpy(s, "[");
    // cout<<x<<endl;
    mpz_init_set_str(temp, x, 16);
    mpz_get_str(x, 10, temp);
    strcat(s, x);
    strcat(s, ", ");
    // cout<<y<<endl;
    mpz_init_set_str(temp, y, 16);
    mpz_get_str(y, 10, temp);
    strcat(s, y);
    strcat(s, "]");
    // cout<<s<<endl;
    element_set_str(*J2, s, 10);
    // element_snprint(s, 256, *J2);
    // cout<<s<<endl;
    mpz_clear(temp);
}

/*
双线性对参数初始化
*/

pairing_t pairing;
element_t P1, P2, Q1, x, y, X, Y, A, B, C, D;
void init_pairing_and_elements() {
    char s[] = "type f q 115792089237314936872688561244471742058375878355761205198700409522629664518163 r 115792089237314936872688561244471742058035595988840268584488757999429535617037 b 3 beta -2 alpha0 1 alpha1 1";
    pairing_init_set_str(pairing, s);

    element_init_G1(P1, pairing);
    element_init_G1(Q1, pairing);
    element_init_G1(A, pairing);
    element_init_G1(B, pairing);
    element_init_G1(C, pairing);
    element_init_G1(D, pairing);

    element_init_G2(P2, pairing);
    element_init_G2(Y, pairing);
    element_init_G2(X, pairing);

    element_init_Zr(x, pairing);
    element_init_Zr(y, pairing);

    element_set_str(P1, "[1, 2]", 10);
    element_random(P2);
}