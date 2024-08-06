/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   ciphertext.cpp
 * Author: muhammad
 * 
 * Created on January 20, 2019, 5:33 PM
 */

#include "ciphertext.hpp"

class IBE;

ciphertext::ciphertext(pairing_t pairing) {
    element_init_G1(U, pairing);
}

ciphertext::ciphertext(const ciphertext& orig) {
}

ciphertext::~ciphertext() {
}

