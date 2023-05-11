#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "ecies_ssl.h"

#define CERT_FILE       "./certs/server/server.crt"
#define KEY_FILE        "./certs/server/server.key"
#define KEY_PASSWD      "111111"

X509* get_x509_from_file(char *filename)
{
    BIO *bio = NULL;
    X509 *x509 = NULL;

    bio = BIO_new_file(filename, "rb");
    if(bio == NULL)
        return NULL;

    x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);

    if(bio) BIO_free_all(bio);
    return x509;
}

EVP_PKEY* get_prvkey_from_file(char *filename, char *passwd)
{
    BIO *bio = NULL;
    EVP_PKEY *prvkey = NULL;

    bio = BIO_new_file(filename, "rb");
    if(bio == NULL)
        return NULL;

    prvkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*)passwd);

    if(bio) BIO_free_all(bio);
    return prvkey;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int tlen = 0;
    unsigned char tpub[256] = {0};
    unsigned char in[] = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    };

    int outlen = 0;
    int txtlen = 0;
    unsigned char out[2048] = {0};
    unsigned char txt[2048] = {0};

    X509 *x509 = NULL;
    EVP_PKEY *pubkey = NULL;
    EVP_PKEY *prvkey = NULL;

    x509 = get_x509_from_file(CERT_FILE);
    if(x509 == NULL)
    {
        fprintf(stderr, "%s %s:%u - get_x509_from_file failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }
    pubkey = X509_get0_pubkey(x509);

    prvkey = get_prvkey_from_file(KEY_FILE, KEY_PASSWD);
    if(prvkey == NULL)
    {
        fprintf(stderr, "%s %s:%u - get_prvkey_from_file failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }

    tlen = sizeof(tpub);
    ret = ecies_encrypt(pubkey, tpub, &tlen, in, sizeof(in), out, &outlen);
    if(ret <= 0)
    {
        fprintf(stderr, "%s %s:%u - ecies_encrypt failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }
    PRINT_HEX("out", out, outlen);
    PRINT_HEX("tpub", tpub, tlen);

    ret = ecies_decrypt(prvkey, tpub, tlen, out, outlen, txt, &txtlen);
    if(ret <= 0)
    {
        fprintf(stderr, "%s %s:%u - ecies_decrypt failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }
    PRINT_HEX("txt", txt, txtlen);

    if(prvkey) EVP_PKEY_free(prvkey);
    if(x509) X509_free(x509);
    return 0;
ErrP:
    if(prvkey) EVP_PKEY_free(prvkey);
    if(x509) X509_free(x509);
    return -1;
}
