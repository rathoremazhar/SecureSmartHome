/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   IBE.hpp
 * Author: muhammad
 *
 * Created on January 20, 2019, 5:30 PM
 */

#ifndef IBE_HPP
#define IBE_HPP

#include <pbc/pbc.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "ciphertext.hpp"
#include "signature.hpp"

class IBE {
    
public:
	pairing_t pairing;
	element_t P; // Generator 
	element_t R; // Generator 
	element_t K; //Network Public Key
    IBE();
	ciphertext encrypt(char msg[], element_t Gid);
	void decrypt(char *dt, struct ciphertext CT, element_t D);
	signature sign(char msg[], element_t Q, element_t D, int inl);
	bool sign_verify(char msg[], signature* s, element_t Q, int inl);
	bool sign_verify(char msg[], signature* s, element_t Q, element_t temp_K, int inl);
    IBE(const IBE& orig);
    virtual ~IBE();
private:
};

#endif /* IBE_HPP */

