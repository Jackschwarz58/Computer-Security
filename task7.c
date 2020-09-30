#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

unsigned char *iv = (unsigned char *)"aabbccddeeff00998877665544332211";
unsigned char *plaintext = (unsigned char *)"What is the date of the first exam?";
unsigned char *ciphertextG = (unsigned char *)"25856d0cb532c339c7937672aa50eab2a682947edd50df8038a81efc1198c13798e83f94e4cf1cb8cbb7e62050510841";

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void string2hexString(char* input, char* output)
{
    int loop;
    int i; 
    
    i=0;
    loop=0;
    
    while(input[loop] != '\0')
    {
        sprintf((char*)(output+i),"%02X", input[loop]);
        loop+=1;
        i+=2;
    }
    //insert NULL at the end of the output string
    output[i++] = '\0';
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int main(void)
{
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    FILE * fp2;

    fp = fopen("words.txt", "r");
    fp2 = fopen("plaintext.txt", "r");
    if (fp == NULL || fp2 == NULL)
        exit(EXIT_FAILURE);


    const char *padding="################";
    while ((read = getline(&line, &len, fp)) != -1) {
        int targetStrLen = 16;           // Target output length  
        char *myString=line;   // String for output 
        strtok(myString, "\n");

        int padLen = targetStrLen - read + 1; // Calc Padding length
        if(padLen < 0) {padLen = 0;}    // Avoid negative length

        char outStr[16];    
        sprintf(outStr,"%s%*.*s", myString, padLen, padLen, padding);  //Padding Words in file

        char hexStr[(strlen(outStr)*2) + 1];
        string2hexString(outStr, hexStr); //Convert Words to hex
        char * key = hexStr; //Set key to that word in hex


        unsigned char ciphertext[128];

        /* Buffer for the decrypted text */
        unsigned char decryptedtext[128];

        int decryptedtext_len, ciphertext_len;

    // /* Encrypt the plaintext */
    //     ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
    //                           ciphertext);

    // /* Do something useful with the ciphertext here */
    //     printf("Ciphertext is:\n");
    //     BIO_dump_fp (stdout, (const char *)ciphertextG, ciphertext_len);

        
        decryptedtext_len = decrypt(*ciphertextG, 96, key, iv, decryptedtext);

        decryptedtext[decryptedtext_len] = '\0';

        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);

    /* Show the decrypted text */
        

    }
    fclose(fp);
    if (line)
        free(line);
    exit(EXIT_SUCCESS);
}
