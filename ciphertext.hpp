/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ciphertext.hpp
 * Author: muhammad
 *
 * Created on January 20, 2019, 5:33 PM
 */

#ifndef CIPHERTEXT_HPP
#define CIPHERTEXT_HPP

#include <pbc/pbc.h>

class ciphertext {
public:
    ciphertext(pairing_t pairing);
    element_t U;
    char V[32];
    char W[32];
    ciphertext(const ciphertext& orig);
    virtual ~ciphertext();
private:
    
};

#endif /* CIPHERTEXT_HPP */

