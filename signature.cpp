/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   signature.cpp
 * Author: muhammad
 * 
 * Created on January 20, 2019, 6:09 PM
 */

#include "signature.hpp"

class IBE;

signature::signature(pairing_t pairing) {
    element_init_G1(U, pairing);
    element_init_G1(V, pairing);
}

signature::signature(const signature& orig) {
}

signature::~signature() {
}

