/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   IBE.cpp
 * Author: muhammad
 * 
 * Created on January 20, 2019, 5:30 PM
 */
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#include "IBE.hpp"
//#include "signature.cpp"

using namespace std;

IBE::IBE() {
    FILE *fp;
    char buf[1024];
    fp = fopen("a.param", "r");
    if (!fp) {
        printf("Error: Cannot open parameter file a.param\n");
        exit(1);
    }
       
    fread(buf, 1, 1000, fp);   
    
    if (pairing_init_set_buf(pairing, buf, 1000)) {
        printf("Pairing initialization failed\n");
        exit(1);
    }
    element_init_G1(P, pairing);
    element_init_G1(K, pairing);
    element_init_G1(R, pairing);
    element_random(P);
    element_random(R);    
    element_set0(K);
  //  signature sig(pairing);
}

IBE::IBE(const IBE& orig) {
}

IBE::~IBE() {
}

ciphertext IBE::encrypt(char msg[], element_t Gid) {
	int i;
	ciphertext ct(pairing);
	element_t r, R, Gr, sigma, sm;
	unsigned char *databytes;
	unsigned char hash[SHA256_DIGEST_LENGTH],gash[SHA256_DIGEST_LENGTH] ;
	unsigned char temp_m[2048];

	element_init_Zr(r, pairing);
	element_init_GT(Gr, pairing);
	element_init_G1(ct.U, pairing);
	element_init_Zr(sigma, pairing);
	element_init_Zr(sm, pairing);
	databytes = (unsigned char *)malloc(element_length_in_bytes(Gid));

	element_random(sigma);	
	
	i = element_to_bytes(databytes, sigma);
	memcpy(temp_m, msg, strlen(msg));
	memcpy(temp_m+strlen(msg), databytes, i);
	SHA256(temp_m, strlen(msg)+i, hash);
		 
	element_from_bytes(r, hash);
	element_mul_zn(ct.U, P, r);
	
	element_pow_zn(Gr, Gid, r);
	i = element_to_bytes(databytes, Gr);
	SHA256(databytes, i, hash);
	i = element_to_bytes(databytes, sigma);
	SHA256(databytes, i, gash);
	for (i = 0; i < 32; i++)
	{
		ct.V[i] = databytes[i] ^ hash[i];
		ct.W[i] = msg[i] ^ gash[i];
	}
	free(databytes);
	return ct;
}
	
void IBE::decrypt(char *dt, ciphertext CT, element_t D) {
	int i;
	unsigned char sigma[32];
	unsigned char *databytes;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	
	element_t DU;
	element_init_GT(DU, pairing);
	
	databytes = (unsigned char *)malloc(element_length_in_bytes(DU));
	element_pairing(DU, CT.U, D);
	
	i = element_to_bytes(databytes, DU);
	SHA256(databytes, i, hash);
	for (i = 0; i < 32; i++)
	{
		sigma[i] = CT.V[i] ^ hash[i];
	}
	
	SHA256(sigma, i, hash);
	for (i = 0; i < 32; i++)
	{
		dt[i] = CT.W[i] ^ hash[i];
	}
	free(databytes);
}

signature IBE::sign(char msg[], element_t Q, element_t D, int inl) {
	int i;
	signature s(pairing);
	unsigned char *databytes;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char temp_m[2048];
	
	element_t r, rh;
	element_t tm, aux, h;
	
	databytes = (unsigned char *)malloc(element_length_in_bytes(Q));
	
	element_init_G1(s.U, pairing);
	element_init_G1(s.V, pairing);
	element_init_Zr(r, pairing);
	element_init_Zr(rh, pairing);
	element_init_Zr(h, pairing);
	element_init_Zr(tm, pairing);
	element_init_G1(aux, pairing);
	
	element_random(r);
	element_mul_zn(s.U, Q, r);
	
	i = element_to_bytes(databytes, s.U);
	memcpy(temp_m, msg, inl);
	memcpy(temp_m+inl, databytes, i);
	
	SHA256(temp_m, inl+i, hash);
	element_from_bytes(h, hash);
	
	element_add(rh, r, h);
	element_mul_zn(s.V, D, rh);
	
	free(databytes);
	return s;	
}	

bool IBE::sign_verify(char msg[], signature* s, element_t Q, int inl) {
    
	int i;
	unsigned char *databytes;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	element_t tm, aux, h, UhQ;
	element_t temp1, temp2;
	unsigned char temp_m[2048];
	
	element_init_Zr(h, pairing);
	element_init_Zr(tm, pairing);
	element_init_G1(aux, pairing);
	element_init_G1(UhQ, pairing);
	element_init_GT(temp1, pairing);
	element_init_GT(temp2, pairing);
	
	databytes = (unsigned char *)malloc(element_length_in_bytes(Q));
	i = element_to_bytes(databytes, s->U);
	memcpy(temp_m, msg, inl);
	memcpy(temp_m+inl, databytes, i);
	
	SHA256(temp_m, inl+i, hash);
	element_from_bytes(h, hash);
	
	element_mul_zn(aux, Q, h);
	element_add(UhQ, s->U, aux);
	
	
	pairing_apply(temp1, P, s->V, pairing);
	pairing_apply(temp2, K, UhQ, pairing);
	
	free(databytes);
	
	if (!element_cmp(temp1, temp2)) 
		return true;
	else
		return false;
}


bool IBE::sign_verify(char msg[], signature* s, element_t Q, element_t temp_K, int inl) {
    
	int i;
	unsigned char *databytes;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	element_t tm, aux, h, UhQ;
	element_t temp1, temp2;
	unsigned char temp_m[2048];
	
	element_init_Zr(h, pairing);
	element_init_Zr(tm, pairing);
	element_init_G1(aux, pairing);
	element_init_G1(UhQ, pairing);
	element_init_GT(temp1, pairing);
	element_init_GT(temp2, pairing);
	
	databytes = (unsigned char *)malloc(element_length_in_bytes(Q));
	i = element_to_bytes(databytes, s->U);
	memcpy(temp_m, msg, inl);
	memcpy(temp_m+inl, databytes, i);
	
	SHA256(temp_m, inl+i, hash);
	element_from_bytes(h, hash);
	
	element_mul_zn(aux, Q, h);
	element_add(UhQ, s->U, aux);
	
	
	pairing_apply(temp1, P, s->V, pairing);
	pairing_apply(temp2, temp_K, UhQ, pairing);
	
	free(databytes);
	
	if (!element_cmp(temp1, temp2)) 
		return true;
	else
		return false;
}
