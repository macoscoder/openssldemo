#include <openssl/bio.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

void md5()
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int size;

    EVP_Digest("hello", 5, md, &size, EVP_md5(), NULL);
    BIO_dump_fp(stdout, md, size);
}

void sha1()
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int size;

    EVP_Digest("hello", 5, md, &size, EVP_sha1(), NULL);
    BIO_dump_fp(stdout, md, size);
}

void sha256()
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int size;

    EVP_Digest("hello", 5, md, &size, EVP_sha256(), NULL);
    BIO_dump_fp(stdout, md, size);
}

void ripemd160()
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int size;

    EVP_Digest("hello", 5, md, &size, EVP_ripemd160(), NULL);
    BIO_dump_fp(stdout, md, size);
}

void sha3_256()
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int size;

    EVP_Digest("hello", 5, md, &size, EVP_sha3_256(), NULL);
    BIO_dump_fp(stdout, md, size);
}

void sm3()
{
    EVP_MD_CTX *ctx;
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int size;

    ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
    EVP_DigestUpdate(ctx, "hello", 5);
    EVP_DigestFinal_ex(ctx, md, &size);
    EVP_MD_CTX_free(ctx);

    BIO_dump_fp(stdout, md, size);
}

int main()
{
    printf("md5:\n");
    md5();

    printf("sha1:\n");
    sha1();

    printf("sha256:\n");
    sha256();

    printf("ripemd160:\n");
    ripemd160();

    printf("sha3_256:\n");
    sha3_256();

    printf("sm3:\n");
    sm3();
}
