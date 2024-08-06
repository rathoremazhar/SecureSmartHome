/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   symmetricCrypto.hpp
 * Author: muhammad
 *
 * Created on January 20, 2019, 6:09 PM
 */

#ifndef SYMMETRIC_CRYPTO_HPP
#define SYMMETRIC_CRYPTO_HPP

#include <openssl/evp.h>

class symmetricCrypto {
public:
    symmetricCrypto();
    unsigned char* sencrypt (EVP_CIPHER_CTX *ctx, unsigned char *data, int inl, int *rb);
    unsigned char* sdecrypt (EVP_CIPHER_CTX * ctx, unsigned char *ct, int inl);
    symmetricCrypto(const symmetricCrypto& orig);
    virtual ~symmetricCrypto();
private:

};

#endif /* SYMMETRIC_CRYPTO_HPP */

