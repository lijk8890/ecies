#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "ecies_ssl.h"

static int evp_encrypt(const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv, unsigned char *in, int inlen, unsigned char *out, int *outlen, int enc)
{
    int ret = 0;
    int length = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    *outlen = 0;
    ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc);
    if(ret != 1)
    {
        fprintf(stderr, "%s %s:%u - EVP_CipherInit_ex failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 1);

    ret = EVP_CipherUpdate(ctx, out, &length, in, inlen);
    if(ret <= 0)
    {
        fprintf(stderr, "%s %s:%u - EVP_CipherUpdate failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }
    *outlen += length;

    ret = EVP_CipherFinal_ex(ctx, out + *outlen, &length);
    if(ret <= 0)
    {
        fprintf(stderr, "%s %s:%u - EVP_CipherFinal_ex failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }
    *outlen += length;

    if(ctx) EVP_CIPHER_CTX_free(ctx);
    return 1;
ErrP:
    ERR_print_errors_fp(stderr);
    if(ctx) EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int ecies_encrypt(EVP_PKEY *pubkey, unsigned char *tpub, int *tlen, unsigned char *in, int inlen, unsigned char *out, int *outlen)
{
    int ret = 0;
    unsigned char skey[32] = {0};
    unsigned char key[16] = {0};
    unsigned char iv[16] = {0};

    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pubkey);
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const EC_POINT *point = EC_KEY_get0_public_key(ec);
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();

    EC_KEY *tkey = EC_KEY_new();
    EC_KEY_set_group(tkey, group);

    ret = EC_KEY_generate_key(tkey);
    if(ret <= 0)
    {
        fprintf(stderr, "%s %s:%u - EC_KEY_generate_key failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }

    ret = ECDH_compute_key(skey, 32, point, tkey, NULL);
    if(ret <= 0)
    {
        fprintf(stderr, "%s %s:%u - ECDH_compute_key failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }
#ifdef __DEBUG__
    PRINT_HEX("ECDH_compute_key", skey, 32);
#endif
    memcpy(key, skey+0, 16);
    memcpy(iv, skey+16, 16);

    ret = evp_encrypt(cipher, key, iv, in, inlen, out, outlen, 1);
    if(ret <= 0)
    {
        fprintf(stderr, "%s %s:%u - evp_encrypt failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }

    const EC_POINT *tpoint = EC_KEY_get0_public_key(tkey);
    *tlen = EC_POINT_point2oct(group, tpoint, POINT_CONVERSION_UNCOMPRESSED, tpub, *tlen, NULL);
    if(*tlen <= 0)
    {
        fprintf(stderr, "%s %s:%u - EC_POINT_point2oct failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }

    if(tkey) EC_KEY_free(tkey);
    return 1;
ErrP:
    ERR_print_errors_fp(stderr);
    if(tkey) EC_KEY_free(tkey);
    return 0;
}

int ecies_decrypt(EVP_PKEY *prvkey, unsigned char *tpub, int tlen, unsigned char *in, int inlen, unsigned char *out, int *outlen)
{
    int ret = 0;
    unsigned char skey[32] = {0};
    unsigned char key[16] = {0};
    unsigned char iv[16] = {0};

    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(prvkey);
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();

    EC_POINT *tpoint = EC_POINT_new(group);
    tlen = EC_POINT_oct2point(group, tpoint, tpub, tlen, NULL);
    if(tlen <= 0)
    {
        fprintf(stderr, "%s %s:%u - EC_POINT_oct2point failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }

    ret = ECDH_compute_key(skey, 32, tpoint, ec, NULL);
    if(ret <= 0)
    {
        fprintf(stderr, "%s %s:%u - ECDH_compute_key failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }
#ifdef __DEBUG__
    PRINT_HEX("ECDH_compute_key", skey, 32);
#endif
    memcpy(key, skey+0, 16);
    memcpy(iv, skey+16, 16);

    ret = evp_encrypt(cipher, key, iv, in, inlen, out, outlen, 0);
    if(ret <= 0)
    {
        fprintf(stderr, "%s %s:%u - evp_decrypt failed\n", __FUNCTION__, __FILE__, __LINE__);
        goto ErrP;
    }

    if(tpoint) EC_POINT_free(tpoint);
    return 1;
ErrP:
    ERR_print_errors_fp(stderr);
    if(tpoint) EC_POINT_free(tpoint);
    return 0;
}
