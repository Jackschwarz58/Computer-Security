#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a) //Given in the PDF
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}


void task1() {
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *pMinus = BN_new();
    BIGNUM *qMinus = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *sum = BN_new();
    BIGNUM *final = BN_new();

    BN_hex2bn(&one, "1");
    BN_sub(pMinus, p, one); //(p-1)
    BN_sub(qMinus, q, one); //(q-1)
    BN_mul(sum, pMinus, qMinus, ctx); //(p-1)(q-1)
    BN_mod_inverse(final, e, sum, ctx); 

    printBN("Private Key Found: ", final);
}

void task2() {
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *final = BN_new();

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&m, "4f554a61636b"); //OUJack
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    BN_CTX *ctx =  BN_CTX_new();

    BN_mod_exp(final, m, e, n, ctx);

    printBN("Encryption Result: ", final);
    printf("\n");

    BIGNUM *check = BN_new(); //To check our result

    BN_mod_exp(check, final, d, n, ctx);

    printBN("Encryption Check (Original Hex):  ", m);
    printf("Encryption Check (Original Ascii):  OUJack\n");
    printBN("Encryption Check (Decrypted Hex): ", check);
    printf("Encryption Check (Decrypted Ascii):  OUJack\n");
}

void task3() {
    BIGNUM *n = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *final = BN_new();

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&m, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    BN_CTX *ctx =  BN_CTX_new();
    BN_mod_exp(final, m, d, n, ctx);

    printBN("Encrypted Message (hex): ", m);
    printBN("Decrypted Message (hex): ", final);
    printf("Intended Solution (hex):  50617373776F72642069732064656573\n");
    printf("Solution in ASCII (ascii): \"Password is dees\"\n");
}

void task4() {
    BIGNUM *n = BN_new();
    BIGNUM *m1 = BN_new(); //Message 1
    BIGNUM *m2 = BN_new(); //Message 2
    BIGNUM *d = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *final1 = BN_new();
    BIGNUM *final2 = BN_new();

    BN_hex2bn(&e, "010001");
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&m1, "49206f7765204a61636b2024313030"); //I owe Jack $100
    BN_hex2bn(&m2, "49206f7765204a61636b2024313130"); //I owe Jack $110
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    BN_CTX *ctx = BN_CTX_new();

    BN_mod_exp(final1, m1, d, n, ctx); //Signing Message 1
    BN_mod_exp(final2, m2, d, n, ctx); //Signing Message 2

    BIGNUM *check1 = BN_new();
    BIGNUM *check2 = BN_new();

    BN_mod_exp(check1, final1, e, n, ctx);
    BN_mod_exp(check2, final2, e, n, ctx);


    printBN("Message 1 Signature: ", final1);
    printBN("Message 2 Signature: ", final2);

    printBN("\nMessage 1 Original: ", m1);
    printBN("Message 2 Original: ", m2);

    printBN("\nSignature 1 Check: ", check1);
    printBN("Signature 2 Check: ", check2);
}

void task5() {
    BIGNUM *n = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *s_corrupt = BN_new(); //Changed last 2 chars
    BIGNUM *e = BN_new();
    BIGNUM *final1 = BN_new();
    BIGNUM *final2 = BN_new(); //To hold decrypted corrupt signature message

    BN_hex2bn(&e, "010001");
    BN_hex2bn(&s, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&s_corrupt, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    BN_CTX *ctx = BN_CTX_new();

    BN_mod_exp(final1, s, e, n, ctx);
    BN_mod_exp(final2, s_corrupt, e, n, ctx);
    
    printBN("Signature: ", s);
    printf("Intended Message (Ascii): Launch a missile.\n");
    printf("Intended Message (Hex):   4C61756E63682061206D697373696C652E\n\n");
    printBN("Decrypted Message (Hex): ", final1);
    printf("Decrypted Message (Ascii): Launch a missile\n\n");

    printBN("Corrupt Signature: ", s_corrupt);
    printBN("Decrypted Corrupted Signature Message (Hex): ", final2);
    printf("Decrypted Corrupted Signature Message (Ascii): G'Èñä,O´cè¼rm=fÈ:N¶·¾´Â\n\n");
}


int main (int argc, char *argv[]){
    printf("\n--------Task 1--------\n\n");
    task1();
    printf("\n--------Task 2--------\n\n");
    task2();
    printf("\n--------Task 3--------\n\n");
    task3();
    printf("\n--------Task 4--------\n\n");
    task4();
    printf("\n--------Task 5--------\n\n");
    task5();
}