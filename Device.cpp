
/* 
 * File:   Device.cpp
 * Author: muhammad
 * 
 * Created on January 20, 2019, 5:30 PM
 */

#include <string.h> 
#include <cstring>
#include <thread> 
#include <unistd.h>
#include <stdbool.h>
#include <iostream>
#include <arpa/inet.h>
#include <sys/socket.h> 
#include <netinet/in.h>
#include <openssl/sha.h>

#include "Device.hpp"
#include "symmetricCrypto.hpp"

using namespace std;

Device::Device(std::string n_id) {
    int i;
    no_of_dev=1;
    memcpy(my_id, n_id.c_str(), ID_SIZE); 
    memcpy(id[0], "AdminPC", ID_SIZE); 
    
    element_init_G1(my_Q, IBE_obj.pairing);
    element_init_Zr(s, IBE_obj.pairing);
    element_init_Zr(r, IBE_obj.pairing);
    element_init_G1(D, IBE_obj.pairing);
    element_init_G1(temp_D, IBE_obj.pairing);
    element_init_G1(temp_Kpub, IBE_obj.pairing);
    element_init_G1(my_COM, IBE_obj.pairing);
    for (i = 0; i < MAX_DEV; i++)
    {
        element_init_GT(G[i], IBE_obj.pairing);
        element_init_G1(Q[i], IBE_obj.pairing);
        element_init_G1(COM[i], IBE_obj.pairing);
        element_init_G1(sP[i], IBE_obj.pairing);
        element_init_G1(sQ[i], IBE_obj.pairing);
    }
    element_from_hash(Q[0], id[0], ID_SIZE);
    element_from_hash(my_Q, my_id, ID_SIZE);
    
    element_random(s);
    element_set0(D);
    element_mul_zn(D, my_Q, s); //initial private key.
    element_printf("My Q-Device: %B\n", my_Q);
    element_printf("My S-Device: %B\n", s);
    RAND_bytes(iv, 16); //Genrate Vector for IV for every device for symetric encryption

    stamp_ptr = new signature(IBE_obj.pairing);
}

int Device::start_Device(string server_ip, int server_port, int t_local_port) {
    printf("Connecting to the server...\n"); 
    local_port = t_local_port;
    struct sockaddr_in address; 
    int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    char buffer[2048] = {0}; 
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(server_port); 
    
    if(inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr)<=0) 
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    } 

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return -1; 
    } 

    printf("Connected successfully to the server\n"); 
    send_message1(sock);
    printf("message 1 sent...\n"); 
    receive_message2(sock);
    printf("message 2 received...\n"); 
    send_message3(sock);
    printf("message 3 sent...\n"); 
    receive_message4p(sock);
    printf("message 4p received...\n"); 
    receive_message4s(sock);
    printf("message 4s received...\n"); 
    receive_message4i(sock);
    printf("message 4i received...\n"); 
    send_message5(sock);
    printf("message 5 sent...\n");
    no_of_dev++;
    receive_broadcast6();
    printf("broadcast 6 received...\n");
    receive_broadcasts7();
    printf("broadcast 7 received...\n");
    exchange_older_messages8();
    printf("messages 8 exchanged with all older devices...\n");
    //keys are calculated after sending message 8

    return 0; 
}

Device::Device(const Device& orig) {
}

Device::~Device() {
}

void Device::update_Gids(){
    for(int i=0; i<no_of_dev; i++)
    {
        element_pairing(G[i], Q[i], IBE_obj.K);
        element_printf("G [%d]: %B\n", i, G[i]);
    }
}

void Device::send_message1(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    memcpy(buffer,"1", 1);
    memcpy(buffer+1, my_id, ID_SIZE);
    memcpy(buffer+8, &local_port, sizeof(int));
    send(server_socket, buffer, SMALL_BUFFER_SIZE, 0); 
}

void Device::receive_message2(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    int valread = read(server_socket , buffer, SMALL_BUFFER_SIZE); 
    if(buffer[0] != '2') //its parameters message
        abort();
    memcpy(pwd, buffer+1, 32);
    memcpy(iv, buffer+1+32, 16);
}

void Device::send_message3(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    memcpy(buffer, pwd, 32);
    memcpy(buffer+32, iv, 16);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)buffer, 48, hash);
    bzero(buffer, SMALL_BUFFER_SIZE);
    memcpy(buffer,"3", 1);
    memcpy(buffer+1, hash, 32);
    send(server_socket, buffer, SMALL_BUFFER_SIZE, 0); 
}

void Device::receive_message4p(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * BUFFER_SIZE);
    bzero(buffer, BUFFER_SIZE);
    int valread = read(server_socket , buffer, BUFFER_SIZE); 
    signature temp_s(IBE_obj.pairing);
    EVP_CIPHER_CTX *ctx;
    if(buffer[0]!='4' || buffer[1]!='p') //its parameters message
        abort();
    ctx = EVP_CIPHER_CTX_new ();
    EVP_DecryptInit_ex ( ctx , EVP_aes_256_cbc () , NULL , pwd , iv );
    symmetricCrypto symmCrypt_obj;
    unsigned char* s_pt = symmCrypt_obj.sdecrypt (ctx, (unsigned char*)buffer+2+256+256, 528+256 );
    unsigned char tempbuff[256];
    memcpy(tempbuff, s_pt, 256);
    element_from_bytes(IBE_obj.P, tempbuff);
    memcpy(tempbuff, s_pt+256, 256);
    element_from_bytes(IBE_obj.K, tempbuff);
    memcpy(tempbuff, s_pt+256+256, 256);
    element_from_bytes(IBE_obj.R, tempbuff);
    memcpy(tempbuff, buffer+2, 256);
    element_from_bytes(temp_s.U, tempbuff);
    memcpy(tempbuff, buffer+2+256, 256);
    element_from_bytes(temp_s.V, tempbuff);
    if(!IBE_obj.sign_verify(buffer+2+256+256, &temp_s, Q[0], 528+256))
    {
        printf("Error: Signature not verified at PWD sharing\n");
        exit(1);
    }
}

void Device::receive_message4s(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * 1100);
    bzero(buffer, 1100);
    int valread = read(server_socket , buffer, 1100); 
    if(buffer[0]!='4' || buffer[1]!='s') //its parameters message
        abort();
    unsigned char tempbuff[256];
    char idl[MAX_DEV*ID_SIZE];
    signature temp_s(IBE_obj.pairing);
    memcpy(&no_of_dev, buffer+2, sizeof(int));
    memcpy(idl, buffer+2+sizeof(int), no_of_dev*ID_SIZE);
    memcpy(tempbuff, buffer+2+sizeof(int)+(no_of_dev*ID_SIZE), 256);
    element_from_bytes(temp_s.U, tempbuff);
    memcpy(tempbuff, buffer+2+sizeof(int)+(no_of_dev*ID_SIZE)+256, 256);
    element_from_bytes(temp_s.V, tempbuff);
    if(!IBE_obj.sign_verify((char *)idl, &temp_s, Q[0], no_of_dev*ID_SIZE))
    {
        printf("-------IDlists not verified\n");
        exit(1);
    }
    memcpy(id, idl, no_of_dev*ID_SIZE);
    for(int i=0;i<no_of_dev;i++)
        element_from_hash(Q[i], id[i], ID_SIZE);
    memcpy(tempbuff, buffer+2+sizeof(int)+(no_of_dev*ID_SIZE)+256+256, 256);
    element_from_bytes(stamp_ptr->U, tempbuff);
    memcpy(tempbuff, buffer+2+sizeof(int)+(no_of_dev*ID_SIZE)+256+256+256, 256);
    element_from_bytes(stamp_ptr->V, tempbuff);
    if(!IBE_obj.sign_verify((char *)my_id, stamp_ptr, Q[0], ID_SIZE))
    {
        printf(".........Stamp not verified\n");
        exit(1);
    }
}

void Device::receive_message4i(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * 1100);
    bzero(buffer, 1100);
    int valread = read(server_socket , buffer, 1048);
    memcpy(list_ip, buffer, IP_ADDRESS_SIZE*no_of_dev);
    valread = read(server_socket , buffer, 1048);
    memcpy(list_ports, buffer, sizeof(int)*no_of_dev);
}

void Device::send_message5(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    unsigned char* databytes = (unsigned char *)malloc(sizeof(unsigned char) * 256);

    element_random(r);
    element_t aux1, aux2;
    element_init_G1(aux1, IBE_obj.pairing);
    element_init_G1(aux2, IBE_obj.pairing);
    element_mul_zn(aux1, IBE_obj.R, r);
    element_mul_zn(aux2, IBE_obj.P, s);
    element_add(my_COM, aux1, aux2);
    element_to_bytes(databytes, my_COM);
    
    memcpy(buffer, pwd, 32);
    memcpy(buffer+32, iv, 16);
    memcpy(buffer+32+16, my_id, ID_SIZE);
    memcpy(buffer+32+16+ID_SIZE, databytes, 256);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)buffer, 16+32+ID_SIZE+256, hash);
    bzero(buffer, SMALL_BUFFER_SIZE);
    memcpy(buffer, "5", 1);
    memcpy(buffer+1, my_id, ID_SIZE);
    memcpy(buffer+1+ID_SIZE, databytes, 256);
    memcpy(buffer+1+ID_SIZE+256, hash, 32);
    send(server_socket, buffer, SMALL_BUFFER_SIZE, 0);
    close(server_socket);
}

void Device::receive_broadcast6() {
    int sd, rc, n, remoteLen;
    struct sockaddr_in localAddr, remoteAddr;
    int broadcast = 1;
    sd=socket(AF_INET, SOCK_DGRAM, 0);
    if(sd<0) {
        printf("Cannot open socket \n");
        exit(1);
    }
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &broadcast, sizeof broadcast) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        exit(1);
    }
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddr.sin_port = htons(BROADCAST_PORT);
    rc = bind (sd, (struct sockaddr *) &localAddr,sizeof(localAddr));
    if(rc<0) {
    printf("Cannot bind port number %d \n", BROADCAST_PORT);
    exit(1);
    }
    printf("Waiting for data on port UDP %u\n",  BROADCAST_PORT);

    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    remoteLen = sizeof(remoteAddr);
    n = recvfrom(sd, buffer, 1+ID_SIZE+256+256+256, 0, NULL, NULL);
    if(n<0) {
        printf("Cannot receive data \n");
    }
    if(buffer[0] != '6')
        abort();
    unsigned char tempbuff[256];
    signature temp_s(IBE_obj.pairing);
    memcpy(tempbuff, buffer+1+ID_SIZE+256, 256);
    element_from_bytes(temp_s.U, tempbuff);
    memcpy(tempbuff, buffer+1+ID_SIZE+256+256, 256);
    element_from_bytes(temp_s.V, tempbuff);
    if(!IBE_obj.sign_verify((char *)buffer+1, &temp_s, Q[0], ID_SIZE+256))
    {
        printf("-------New device commitment request from admin is not verified\n");
        exit(1);
    }
    memcpy(&COM[no_of_dev-1], buffer+1+ID_SIZE, 256);
    memcpy(&id[no_of_dev-1], buffer+1, ID_SIZE);
    //printf("From %s:UDP%u\n", inet_ntoa(remoteAddr.sin_addr), ntohs(remoteAddr.sin_port));
}

void Device::receive_broadcasts7() {
    int rec_no_coms;
    thread tid[no_of_dev-1];
    for (rec_no_coms=0; rec_no_coms<no_of_dev-1; rec_no_coms++) {
        tid[rec_no_coms] = thread(&Device::process_broadcast7, this);
    }
    for (rec_no_coms=0; rec_no_coms<no_of_dev-1; rec_no_coms++) {
        tid[rec_no_coms].join();
    }
}

void Device::process_broadcast7() {
    int sd, rc, n, remoteLen;
    struct sockaddr_in localAddr, remoteAddr;
    int broadcast = 1;
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sd<0) {
        printf("Cannot open socket \n");
        exit(1);
    }
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &broadcast, sizeof(broadcast)) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        exit(1);
    }
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddr.sin_port = htons(BROADCAST_PORT);
    rc = bind (sd, (struct sockaddr *) &localAddr, sizeof(localAddr));
    if(rc<0) {
    printf("Cannot bind port number %d \n", BROADCAST_PORT);
    exit(1);
    }
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    n = recvfrom(sd, buffer, SMALL_BUFFER_SIZE, 0, NULL, NULL);
    if(buffer[0] != '7')
        abort();
    unsigned char tempbuff[256];
    signature temp_s(IBE_obj.pairing);
    memcpy(tempbuff, buffer+1+ID_SIZE+256, 256);
    element_from_bytes(temp_s.U, tempbuff);
    memcpy(tempbuff, buffer+1+ID_SIZE+256+256, 256);
    element_from_bytes(temp_s.V, tempbuff);
    int device_id = get_id_index(buffer+1);
    if(!IBE_obj.sign_verify((char *)buffer+1, &temp_s, Q[device_id], ID_SIZE+256))
    {
        printf("-------Commitment from admin is not verified\n");
        exit(1);
    }
    element_from_bytes(COM[device_id], (unsigned char*)buffer+1+ID_SIZE);
}
void Device::exchange_older_messages8(){
    cout<<"...........sdfj fjksdhjfhdsjhf ";
    int device_no = 0;
    int my_index = get_id_index(my_id);
    cout<<my_index;
    thread tid[my_index];
    for (device_no=0; device_no<my_index; device_no++) {
        tid[device_no] = thread(&Device::process_message8, this);
    }
    for (device_no=0; device_no<my_index; device_no++) {
        tid[device_no].join();
    }
}

void Device::process_message8() {
    //opening the socket with the device
    int sd, rc, n, remoteLen;
    struct sockaddr_in localAddr, remoteAddr;
    int broadcast = 1;
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sd<0) {
        printf("Cannot open socket \n");
        exit(1);
    }
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &broadcast, sizeof(broadcast)) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        exit(1);
    }
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddr.sin_port = htons(local_port);
    rc = bind (sd, (struct sockaddr *) &localAddr, sizeof(localAddr));
    if(rc<0) {
    printf("Cannot bind port number %d \n", local_port);
    exit(1);
    }
    char *buffer = (char *) malloc(sizeof(char) * BUFFER_SIZE);
    bzero(buffer, BUFFER_SIZE);
    n = recvfrom(sd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if(buffer[0] != '8')
        abort();

    //receiving secret share values to the device
    element_t aux1, aux2, t_r;
    element_init_G1(aux1, IBE_obj.pairing);
    element_init_G1(aux2, IBE_obj.pairing);
    element_init_Zr(t_r, IBE_obj.pairing);
    element_set0(aux1);
    unsigned char tempbuff[256];
    signature temp_s(IBE_obj.pairing);
    int device_id = 0;
    bzero(tempbuff, 256);
    memcpy(tempbuff, buffer+1+ID_SIZE+256+256+256, 256);
    element_from_bytes(temp_s.U, tempbuff);
    memcpy(tempbuff, buffer+1+ID_SIZE+256+256+256+256, 256);
    element_from_bytes(temp_s.V, tempbuff);
    device_id = get_id_index(buffer+1);
    if (device_id == no_of_dev-1) {
        if(!IBE_obj.sign_verify((char *)buffer+1, &temp_s, Q[0], ID_SIZE+256+256+256))
        {
            printf("-------Secret sharing message from the new device (stamp) is not verified\n");
            exit(1);
        }
    } 
    else {
        if(!IBE_obj.sign_verify((char *)buffer+1, &temp_s, Q[device_id], ID_SIZE+256+256+256))
        {
            printf("-------Secret sharing message is not verified\n");
            exit(1);
        }
    }
    element_from_bytes(t_r, (unsigned char*)buffer+1+ID_SIZE);
    element_from_bytes(aux1, (unsigned char*)buffer+1+ID_SIZE+256);
    element_from_bytes(aux2, (unsigned char*)buffer+1+ID_SIZE+256+256);
    if (!Com_verify(aux1, t_r, COM[device_id])) {
        cout << "-------Commitment from device " << id[device_id] << " is not verified" << endl;
        exit(1);
    }
    element_set(sP[device_id], aux1);
    element_set(sQ[device_id], aux2);
    
    //sending secret share values to the device
    element_mul_zn(aux1, IBE_obj.P, s); //aux1 = sP
    bzero(buffer, BUFFER_SIZE);
    element_set0(aux2);
    element_mul_zn(aux2, Q[device_id], s);   //aux2= sQ
    memcpy(buffer, "8", 1);
    memcpy(buffer+1, my_id, ID_SIZE);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE, r);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256, aux1);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256+256, aux2);
    temp_s = IBE_obj.sign(buffer+1, my_Q, D, ID_SIZE+256+256+256);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256+256+256, temp_s.U);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256+256+256+256, temp_s.V);
    send(sd, buffer, BUFFER_SIZE, 0);
}

int Device::get_id_index(char* t_id) {
    int index = -1;
    for (int i=0; i<no_of_dev; i++)
        if (memcmp(id[i], t_id, 7) == 0)
            index = i;
    return index;
}

void Device::Compute_Network_Public_Key(element_t *t_sp){
    element_set0(temp_Kpub);
    for (int i=0;i<no_of_dev; i++)
    {
        element_add(temp_Kpub, temp_Kpub, t_sp[i]);
    }
}

void Device::Compute_Private_Key(element_t *t_sq){
    element_set0(temp_D);
    for (int i=0;i<no_of_dev; i++)
    {
        element_add(temp_D, temp_D, t_sq[i]);
    }
}

bool Device::Com_verify(element_t t_sp,element_t t_r,element_t t_com){
    element_t aux;
    element_init_G1(aux, IBE_obj.pairing);
    element_mul_zn(aux, t_r, IBE_obj.R);
    element_add(aux, aux, t_sp);
    if (!element_cmp(aux, t_com))
    {
        return true;
    }
    else
    {
        return false;
    }
}
