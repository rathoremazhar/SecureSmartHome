/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   signature.hpp
 * Author: muhammad
 *
 * Created on January 20, 2019, 6:09 PM
 */

#ifndef SIGNATURE_HPP
#define SIGNATURE_HPP

#include <pbc/pbc.h>

class signature {
public:
    signature(pairing_t pairing);
    element_t U;
    element_t V;
    signature(const signature& orig);
    virtual ~signature();
private:

};

#endif /* SIGNATURE_HPP */

