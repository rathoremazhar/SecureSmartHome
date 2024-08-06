/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   symmetricCrypto.cpp
 * Author: muhammad
 * 
 * Created on January 20, 2019, 6:09 PM
 */

#include "symmetricCrypto.hpp"

symmetricCrypto::symmetricCrypto() {
    
}

symmetricCrypto::symmetricCrypto(const symmetricCrypto& orig) {
}

symmetricCrypto::~symmetricCrypto() {
}

unsigned char* symmetricCrypto::sencrypt (EVP_CIPHER_CTX *ctx, unsigned char *data, int inl, int *rb) {
	unsigned char *result; /* the encrypted result returned by the function */
	int tmp, outl;
	/* because of padding , we need one extra block to hold the result */
	result = (unsigned char *) malloc ( inl + EVP_CIPHER_CTX_block_size(ctx));
	EVP_EncryptUpdate (ctx, result, &outl, data, inl);
	EVP_EncryptFinal_ex(ctx ,result + outl, &tmp);
	/* compute ciphertext size */
	*rb = outl + tmp;
	return result;
}


/* Symetric Decryption function (AES)
- ct : ciphertext buffer
- inl : ciphertext length ( bytes )
- returns a pointer to the plaintext buffer
- we don ’t need to return the plaintext size , as it ’s a C - string
*/
unsigned char* symmetricCrypto::sdecrypt (EVP_CIPHER_CTX * ctx, unsigned char *ct, int inl) {
	unsigned char * result ; /* the plaintext result returned by the function */
	int tmp , outl;
	result = ( unsigned char *) malloc ( inl );
	EVP_DecryptUpdate (ctx,result,&outl,ct,inl);
	if (! EVP_DecryptFinal (ctx,result+outl,&tmp))
	{
		printf ("Padding incorrect .\n " );
		abort ();
	}
	return result ;
}
