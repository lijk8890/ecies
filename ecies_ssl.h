#ifndef __ECIES_SSL_H__
#define __ECIES_SSL_H__

#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/err.h"
#include "openssl/ssl.h"

#ifdef __cplusplus
extern "C"
{
#endif

int ecies_encrypt(EVP_PKEY *pubkey, unsigned char *tpub, int *tlen, unsigned char *in, int inlen, unsigned char *out, int *outlen);

int ecies_decrypt(EVP_PKEY *prvkey, unsigned char *tpub, int tlen, unsigned char *in, int inlen, unsigned char *out, int *outlen);

#ifdef __cplusplus
}
#endif

#endif
