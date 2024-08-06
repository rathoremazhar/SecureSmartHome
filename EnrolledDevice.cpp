
/* 
 * File:   EnrolledDevice.cpp
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
#include <netdb.h>
#include <sys/time.h>

#include "EnrolledDevice.hpp"
#include "symmetricCrypto.hpp"

using namespace std;

EnrolledDevice::EnrolledDevice() {
}

void EnrolledDevice::set_Parameters(IBE* t_IBE_obj, int t_no_of_dev, char* t_my_id, char t_id[][7], char t_list_ip[][IP_ADDRESS_SIZE], int t_list_ports[], int t_local_port, element_t t_my_Q, element_t t_D, element_t t_Q[], unsigned char t_iv[], int t_list_comm_ports[], int t_local_comm_port) {
    
    IBE_obj = t_IBE_obj;

    element_init_Zr(s, IBE_obj->pairing);
    element_init_Zr(r, IBE_obj->pairing);
    element_init_G1(temp_D, IBE_obj->pairing);
    element_init_G1(temp_Kpub, IBE_obj->pairing);
    element_init_G1(my_COM, IBE_obj->pairing);
    element_init_G1(D, IBE_obj->pairing);
    element_init_G1(my_Q, IBE_obj->pairing);
    for (int i = 0; i < MAX_DEV; i++)
    {
        element_init_GT(G[i], IBE_obj->pairing);
        element_init_G1(COM[i], IBE_obj->pairing);
        element_init_G1(Q[i], IBE_obj->pairing);
        element_init_G1(sP[i], IBE_obj->pairing);
        element_init_G1(sQ[i], IBE_obj->pairing);
    }

    no_of_dev = t_no_of_dev; 
    my_id = t_my_id;
    memcpy(id, t_id, t_no_of_dev*ID_SIZE);
    memcpy(iv, t_iv, 16);
    memcpy(list_ip, t_list_ip, t_no_of_dev*IP_ADDRESS_SIZE);
    memcpy(list_ports, t_list_ports, t_no_of_dev*sizeof(int));
    memcpy(list_comm_ports, t_list_comm_ports, t_no_of_dev*sizeof(int));
    local_port = t_local_port;
    local_comm_port = t_local_comm_port;
    element_set(my_Q, t_my_Q);
    element_set(D, t_D);
    for (int i=0; i<no_of_dev; i++)
        element_set(Q[i], t_Q[i]);
}

int EnrolledDevice::start_Device() {
    cout << "start_Device" << endl;
    thread regular_operations_thread = thread(&EnrolledDevice::Perform_regular_operations, this);
    //thread message_K_thread = thread(&EnrolledDevice::Wait_for_message_K, this);
    regular_operations_thread.join();
    return 0; 
}

void EnrolledDevice::Wait_for_message_K() {
    int server_fd, new_socket, valread, prev_valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 

    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
    // Forcefully attaching socket to the port 8080 
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(local_comm_port); 
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(server_fd, MAX_DEV) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    }
    thread keyExchangeThread[MAX_DEV];
    int noKeyExchanges = 0;
    while(1) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        char buffer[SMALL_BUFFER_SIZE];
        bzero(buffer, SMALL_BUFFER_SIZE);

        size_t recBytes = 0;
        while (recBytes<SMALL_BUFFER_SIZE)
            recBytes += read(new_socket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
        if (recBytes < 0) perror("ERROR reading socket");
        if (buffer[0] == 'K'){
            printf("receiving message K...\n"); 
            keyExchangeThread[noKeyExchanges] = thread(&EnrolledDevice::Receive_Session_key_Exchange, this, new_socket, buffer);
            noKeyExchanges++;
        }
        else
            printf("ERROR receiving message K...\n"); 
    }
    close(server_fd);
}

void EnrolledDevice::Receive_Session_key_Exchange(int client_socket, char* buffer) {
    int remoteDeviceIndex = get_id_index(buffer+1);
    unsigned char TK[256];
    int j;
    unsigned char temp_skey[256];
    ctx = EVP_CIPHER_CTX_new();
    element_t aux_gt, aux_g1, aux_R, my_r, rec_rp, my_R, rec_R;

    element_init_GT(aux_gt, IBE_obj->pairing);
    element_init_G1(aux_g1, IBE_obj->pairing);
    element_init_Zr(my_r, IBE_obj->pairing);
    element_init_G1(rec_rp, IBE_obj->pairing);
    element_init_Zr(aux_R, IBE_obj->pairing);
    element_init_Zr(my_R, IBE_obj->pairing);
    element_init_Zr(rec_R, IBE_obj->pairing);
    pairing_apply(aux_gt, Q[remoteDeviceIndex], D, IBE_obj->pairing);
    element_to_bytes(TK, aux_gt);
    symmetricCrypto symmCrypt_obj;
    EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc(), NULL, TK, iv);
    unsigned char* s_pt = symmCrypt_obj.sdecrypt (ctx, (unsigned char*)buffer+1+ID_SIZE, 272);
    element_random(my_r);
    element_from_bytes(rec_rp, s_pt);
    element_mul_zn(aux_g1, rec_rp, my_r); // K = rj.ri.P
    element_to_bytes(temp_skey, aux_g1);
    //K1 recieved/////////

    element_mul_zn(aux_g1, IBE_obj->P, my_r); // rj.P
    element_to_bytes((unsigned char*)buffer, aux_g1); //rj.P
    EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc() , NULL , TK , iv);
    unsigned char* s_ct1 = symmCrypt_obj.sencrypt(ctx, (unsigned char*)buffer, 256, &j); //j=272
    element_random(my_R);
    element_to_bytes((unsigned char*)buffer, my_R); //rj.P
    EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc() , NULL , temp_skey , iv);
    unsigned char* s_ct2 = symmCrypt_obj.sencrypt(ctx, (unsigned char*)buffer, 256, &j); //j=272
    bzero(buffer, SMALL_BUFFER_SIZE);
    memcpy(buffer, s_ct1, 272);
    memcpy(buffer+272, s_ct2, 272);
    send(client_socket, buffer, SMALL_BUFFER_SIZE, 0);
    //K2 sent//////////////////

    bzero(buffer, SMALL_BUFFER_SIZE);
    size_t recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE)
        recBytes += read(client_socket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR reading socket");
    EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc(), NULL, temp_skey, iv);
    s_pt = symmCrypt_obj.sdecrypt (ctx, (unsigned char*)buffer, 528);
    element_from_bytes(rec_R, s_pt); //rj.P
    element_from_bytes(aux_R, s_pt+256); //rj.P
    if (element_cmp(aux_R, my_R))
        perror("ERROR rec_R and my_R are not the same");
    //K3 received/////////////////////////

    memcpy(s_key[remoteDeviceIndex], temp_skey, 256);

    bzero(buffer, SMALL_BUFFER_SIZE);
    EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc() , NULL , temp_skey , iv);
    s_ct2 = symmCrypt_obj.sencrypt(ctx, s_pt, 256, &j); //j=272
    memcpy(buffer, s_ct2, 272);
    send(client_socket, buffer, SMALL_BUFFER_SIZE, 0);
    //K4 sent//////////////////

    cout << "Session_key_Exchange successfull" << endl;
}

void EnrolledDevice::Perform_regular_operations() {
    while (1) {
        no_of_dev++;
        receive_broadcast6();
        //cout << "my_id=" << my_id << " no_of_dev=" << no_of_dev << endl;
        int my_index = get_id_index(my_id);
        //cout << "my_id=" << my_id << " my_index=" << my_index << endl;
        printf("broadcast 6 received...\n");
        receive_broadcasts7(my_index);
        printf("older devices broadcasts 7 received...\n");
        broadcast_message7();
        printf("broadcast 7 sent...\n");
        receive_broadcasts7(no_of_dev-my_index-2);
        printf("newer devices broadcasts 7 received...\n");
        exchange_older_messages8();
        printf("older devices messages 8 exchanged with all older devices...\n");
        exchange_newer_messages8();
        printf("newer devices messages 8 exchanged with all newer devices...\n");
        //keys are calculated after sending message 8
        Compute_Network_Public_Key(sP);
        Compute_Private_Key(sQ);

        send_messageA();
        printf("message A sent...\n"); 
        receive_broadcast9();
        printf("broadcast9 recieved!\n"); 
    
        element_set(IBE_obj->K, temp_Kpub);
        element_set(D, temp_D);
        cout << "keys have been updated successfully!" << endl;
    }
}

EnrolledDevice::EnrolledDevice(const EnrolledDevice& orig) {
}

EnrolledDevice::~EnrolledDevice() {
}

void EnrolledDevice::update_Gids(){
    for(int i=0; i<no_of_dev; i++)
        element_pairing(G[i], Q[i], IBE_obj->K);
}

void EnrolledDevice::receive_broadcast6() {
    int listeningSocket = socket(PF_INET, SOCK_DGRAM, 0);
    int broadcast = 1;
    if (listeningSocket <= 0) {
        perror("Error: listenForPackets - socket() failed.");
        return;
    }
    if (setsockopt(listeningSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &broadcast, sizeof broadcast) == -1) {
        perror("Error: listenForPackets - setsockopt failed");
        close(listeningSocket);
        return;
    }
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(BROADCAST_PORT);
    sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    int status = bind(listeningSocket, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (status == -1) {
        close(listeningSocket);
        perror("Error: listenForPackets - bind() failed.");
        return;
    }
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    struct sockaddr_in receiveSockaddr;
    socklen_t receiveSockaddrLen = sizeof(receiveSockaddr);
    printf("Waiting for broadcast6 on port UDP:: %u\n",  BROADCAST_PORT);
    int recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE) {
        recBytes += recvfrom(listeningSocket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes, 0, (struct sockaddr *)&receiveSockaddr, &receiveSockaddrLen);
    }
    if (recBytes < 0) perror("ERROR while reading the db version");
    cout << "buffer=" << buffer << endl;

    if(buffer[0] != '6') {
        cout << "at receive_broadcast6" << endl;
        abort();
    }
    unsigned char tempbuff[256];
    bzero(tempbuff, 256);
    signature temp_s(IBE_obj->pairing);
    memcpy(tempbuff, buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int)+256, 256);
    element_from_bytes(temp_s.U, tempbuff);
    memcpy(tempbuff, buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int)+256+256, 256);
    element_from_bytes(temp_s.V, tempbuff);
    if(!IBE_obj->sign_verify((char *)buffer+1, &temp_s, Q[0], ID_SIZE+IP_ADDRESS_SIZE+sizeof(int)+256))
    {
        printf("-------New device commitment request from admin is not verified\n");
        exit(1);
    }
    element_from_bytes(COM[no_of_dev-1], (unsigned char*)buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int));
    memcpy(&id[no_of_dev-1], buffer+1, ID_SIZE);
    //cout<< "New Device ID :" << id[no_of_dev-1] <<endl;
    element_from_hash(Q[no_of_dev-1], id[no_of_dev-1], ID_SIZE);

    memcpy(&list_ip[no_of_dev-1], buffer+1+ID_SIZE, IP_ADDRESS_SIZE);
    memcpy(&list_ports[no_of_dev-1], buffer+1+ID_SIZE+IP_ADDRESS_SIZE, sizeof(int));
    memcpy(&list_comm_ports[no_of_dev-1], buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int), sizeof(int));
}

void EnrolledDevice::receive_broadcasts7(int no_broadcasts) {
    if (no_broadcasts<1)
        return;
    thread tid[no_broadcasts];
    int listeningSocket = socket(PF_INET, SOCK_DGRAM, 0);
    int broadcast = 1;
    if (listeningSocket <= 0) {
        perror("Error: listenForPackets - socket() failed.");
        return;
    }
    if (setsockopt(listeningSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &broadcast, sizeof broadcast) == -1) {
        perror("Error: listenForPackets - setsockopt failed");
        close(listeningSocket);
        return;
    }
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(BROADCAST_PORT);
    sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    int status = bind(listeningSocket, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (status == -1) {
        close(listeningSocket);
        perror("Error: listenForPackets - bind() failed.");
        return;
    }
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    struct sockaddr_in receiveSockaddr;
    socklen_t receiveSockaddrLen = sizeof(receiveSockaddr);
    printf("Waiting for broadcast7 on port UDP:: %u\n",  BROADCAST_PORT);

    for (int rec_no_broadcasts=0; rec_no_broadcasts<no_broadcasts; rec_no_broadcasts++) {
        int recBytes = 0;
        while (recBytes<SMALL_BUFFER_SIZE)
            //recBytes += read(server_socket , buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
            recBytes += recvfrom(listeningSocket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes, 0, (struct sockaddr *)&receiveSockaddr, &receiveSockaddrLen);
        if (recBytes < 0) perror("ERROR while reading the db version");
        tid[rec_no_broadcasts] = thread(&EnrolledDevice::process_broadcast7, this, buffer);
    }
    for (int rec_no_broadcasts=0; rec_no_broadcasts<no_broadcasts; rec_no_broadcasts++) {
        tid[rec_no_broadcasts].join();
    }
}

void EnrolledDevice::process_broadcast7(char *buffer) {
    printf("process_broadcast7:broadcast7 recieved on port UDP:: %u\n",  BROADCAST_PORT);
    struct timeval now;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;

    if(buffer[0] != '7') {
        cout << "at process_broadcast7" << endl;
        abort();
    }
    unsigned char tempbuff[256];
    signature temp_s(IBE_obj->pairing);
    memcpy(tempbuff, buffer+1+ID_SIZE+256, 256);
    element_from_bytes(temp_s.U, tempbuff);
    memcpy(tempbuff, buffer+1+ID_SIZE+256+256, 256);
    element_from_bytes(temp_s.V, tempbuff);
    int device_id = get_id_index(buffer+1);
    if(!IBE_obj->sign_verify((char *)buffer+1, &temp_s, Q[device_id], ID_SIZE+256))
    {
        printf("-------Commitment from admin is not verified\n");
        exit(1);
    }
    element_from_bytes(COM[device_id], (unsigned char*)buffer+1+ID_SIZE);
    //close(sd);
}

void EnrolledDevice::broadcast_message7() {
    char buffer[SMALL_BUFFER_SIZE];
    bzero(buffer, SMALL_BUFFER_SIZE);
    unsigned char* databytes = (unsigned char *)malloc(sizeof(unsigned char) * 256);

    signature temp_s(IBE_obj->pairing);
    element_random(r);
    element_random(s);
    element_t aux1, aux2;
    element_init_G1(aux1, IBE_obj->pairing);
    element_init_G1(aux2, IBE_obj->pairing);
    element_mul_zn(aux1, IBE_obj->R, r);
    element_mul_zn(aux2, IBE_obj->P, s);
    element_add(my_COM, aux1, aux2);
    element_to_bytes(databytes, my_COM);
   
    memcpy(buffer, "7", 1);
    memcpy(buffer+1, my_id, ID_SIZE);
    memcpy(buffer+1+ID_SIZE, databytes, 256);

    temp_s = IBE_obj->sign(buffer+1, my_Q, D, ID_SIZE+256);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256, temp_s.U);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256+256, temp_s.V);
    
    int sd, rc, i;
    struct sockaddr_in localAddr, remoteAddr;
    struct hostent *h;
    int broadcast = 1;
    h = gethostbyname(BROADCAST_ADDRESS.c_str());
    //printf("Snding data to '%s' (IP : %s) \n", h->h_name, inet_ntoa(*(struct in_addr *)h->h_addr_list[0]));
    remoteAddr.sin_family = h->h_addrtype;
    memcpy((char *) &remoteAddr.sin_addr.s_addr, h->h_addr_list[0], h->h_length);
    remoteAddr.sin_port = htons(BROADCAST_PORT);
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sd<0) {
        printf("Cannot open socket \n");
        exit(1);
    }
    if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof broadcast) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        exit(1);
    }
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddr.sin_port = htons(0);
    rc = bind(sd, (struct sockaddr *) &localAddr, sizeof(localAddr));
    if(rc<0) {
        printf("Cannot bind port\n");
        exit(1);
    }
    rc = sendto(sd, buffer, SMALL_BUFFER_SIZE, 0, (struct sockaddr *) &remoteAddr, sizeof(remoteAddr));
    if(rc<0) {
        printf("Cannot send data %d \n", i-1);
        exit(1);
    }

    cout << "broadcast_message7: broadcast_message7"<< endl;
    struct timeval now;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
    close(sd);
}

void EnrolledDevice::exchange_older_messages8(){
    int device_no = 0;
    int my_index = get_id_index(my_id);
    thread tid[my_index];

    int sd, new_socket, valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(local_port); 
    if (bind(sd, (struct sockaddr *)&address, sizeof(address))<0) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
    if (listen(sd, MAX_DEV) < 0) 
    { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    }

    struct timeval now;
    for (device_no=0; device_no<my_index; device_no++) {
        cout << "exchange_older_messages8: waiting for: " << my_index-device_no << " messages 8, on port: " << local_port << " no_of_dev:" << no_of_dev <<  endl;
        gettimeofday(&now,NULL);
        cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
        new_socket = accept(sd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        cout << "exchange_older_messages8: accepted socket=" << new_socket << endl;
        gettimeofday(&now,NULL);
        cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
        tid[device_no] = thread(&EnrolledDevice::process_message8, this, new_socket);
    }
    for (device_no=0; device_no<my_index; device_no++) {
        tid[device_no].join();
    }

    element_t aux1, aux2;
    element_init_G1(aux1, IBE_obj->pairing);
    element_init_G1(aux2, IBE_obj->pairing);
    element_mul_zn(aux1, IBE_obj->P, s); //aux1 = sP
    element_mul_zn(aux2, my_Q, s); //aux1 = sP
    element_set(sP[my_index], aux1);
    element_set(sQ[my_index], aux2);
}

void EnrolledDevice::process_message8(int new_socket) {
    struct timeval now;
    if (new_socket < 0) perror("ERROR on accept");
    char *buffer = (char *) malloc(sizeof(char) * BUFFER_SIZE);
    bzero(buffer, BUFFER_SIZE);

    cout << "process_message8: reading message8 from socket: " << new_socket << "..." << endl;
    size_t recBytes = 0;
    while (recBytes<BUFFER_SIZE)
        recBytes += read(new_socket, buffer+recBytes, BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR reading socket");
    cout << "process_message8: message8 received" << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;

    //read(new_socket, buffer, BUFFER_SIZE);
    if(buffer[0] != '8')
        abort();

    //receiving secret share values to the device
    element_t aux1, aux2, t_r;
    element_init_G1(aux1, IBE_obj->pairing);
    element_init_G1(aux2, IBE_obj->pairing);
    element_init_Zr(t_r, IBE_obj->pairing);
    element_set0(aux1);
    int device_id = 0;
    device_id = get_id_index(buffer+1);
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
    element_mul_zn(aux1, IBE_obj->P, s); //aux1 = sP
    bzero(buffer, BUFFER_SIZE);
    element_set0(aux2);
    element_mul_zn(aux2, Q[device_id], s);   //aux2= sQ

    memcpy(buffer, "8", 1);
    memcpy(buffer+1, my_id, ID_SIZE);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE, r);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256, aux1);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256+256, aux2);



    cout << "process_message8:sending message8 to " << list_ip[device_id] << ":" << list_ports[device_id] << "..." << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
    send(new_socket, buffer, BUFFER_SIZE, 0);
    cout << "process_message8:message 8 sent successfully to " << list_ip[device_id] << ":" << list_ports[device_id] << "" << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
}

void EnrolledDevice::exchange_newer_messages8() {
    struct timeval now;
    int my_index = get_id_index(my_id);
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    int socketsList[no_of_dev];
    for (int device_index=my_index+1; device_index<no_of_dev; device_index++) {
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        { 
            printf("\n Socket creation error \n"); 
            exit(1);
        } 
        memset(&serv_addr, '0', sizeof(serv_addr)); 
        serv_addr.sin_family = AF_INET; 
        serv_addr.sin_port = htons(list_ports[device_index]); 

        cout << "exchange_newer_messages8: opening socket with device " << device_index << " : " << list_ip[device_index] << ":" << list_ports[device_index] << "" << endl;
        gettimeofday(&now,NULL);
        cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;

        if(inet_pton(AF_INET, list_ip[device_index], &serv_addr.sin_addr)<=0) 
        { 
            printf("\nInvalid address/ Address not supported \n"); 
            exit(1);
        } 
        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
        { 
            printf("\nConnection Failed \n"); 
            exit(1);
        } 
        socketsList[device_index] = sock;
    }

    cout << "exchange_newer_messages8: all " << no_of_dev-my_index+1 << " sockets have been opened successfully" << endl;

    element_t aux1, aux2, t_r;
    element_init_Zr(t_r, IBE_obj->pairing);
    element_init_G1(aux1, IBE_obj->pairing);
    element_init_G1(aux2, IBE_obj->pairing);
    element_set0(aux1);
    element_mul_zn(aux1, IBE_obj->P, s); //aux1 = sP
    element_mul_zn(aux2, my_Q, s); //aux1 = sQ
    element_set(sP[my_index], aux1);
    element_set(sQ[my_index], aux2);
    int device_id = 0;
    char buffer[BUFFER_SIZE];
    for (int device_index=my_index+1; device_index<no_of_dev; device_index++) {
        //sending secret share values to the device
        bzero(buffer, BUFFER_SIZE);
        element_set0(aux2);
        element_mul_zn(aux2, Q[device_index], s);   //aux2= sQ
        element_mul_zn(aux1, IBE_obj->P, s); //aux1 = sP
        memcpy(buffer, "8", 1);
        memcpy(buffer+1, my_id, ID_SIZE);
        element_to_bytes((unsigned char*)buffer+1+ID_SIZE, r);
        element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256, aux1);
        element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256+256, aux2);
        
    cout << "exchange_newer_messages8: sending message8 to " << list_ip[device_index] << ":" << list_ports[device_index] << " ..." << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
        send(socketsList[device_index], buffer, BUFFER_SIZE, 0);
    cout << "exchange_newer_messages8: message 8 sent to " << list_ip[device_index] << ":" << list_ports[device_index] << "" << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;

        //receiving secret share values to the device
        bzero(buffer, BUFFER_SIZE);
    cout << "exchange_newer_messages8: receiving from " << list_ip[device_index] << ":" << list_ports[device_index] << " message8..." << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
        size_t recBytes = 0;
        while (recBytes<BUFFER_SIZE)
            recBytes += read(socketsList[device_index] , buffer+recBytes, BUFFER_SIZE-recBytes);
        if (recBytes < 0) perror("ERROR reading socket");
    cout << "exchange_newer_messages8: messages8 received from " << list_ip[device_index] << ":" << list_ports[device_index] << "" << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;

        //valread = read(socketsList[device_index], buffer, BUFFER_SIZE);
        if(buffer[0]!='8') //its parameters message
            exit(1);
        device_id = get_id_index(buffer+1);
        element_from_bytes(t_r, (unsigned char*)buffer+1+ID_SIZE);
        element_from_bytes(aux1, (unsigned char*)buffer+1+ID_SIZE+256);
        element_from_bytes(aux2, (unsigned char*)buffer+1+ID_SIZE+256+256);
        if (!Com_verify(aux1, t_r, COM[device_id])) {
            cout << "-------Commitment from device " << id[device_id] << " is not verified" << endl;
            exit(1);
        }
        element_set(sP[device_id], aux1);
        element_set(sQ[device_id], aux2);
    }
}

void EnrolledDevice::send_messageA() {
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        exit(1);
    } 
    memset(&serv_addr, '0', sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(list_ports[0]); 

    cout << "opening socket with device " << 0 << " : " << list_ip[0] << ":" << list_ports[0] << endl;

    if(inet_pton(AF_INET, list_ip[0], &serv_addr.sin_addr)<=0) 
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        exit(1);
    } 
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        exit(1);
    } 
    int key_verified = verify_keys();
    cout << "send_messageA:key verification: " << key_verified << endl;
    char buffer[SMALL_BUFFER_SIZE];
    bzero(buffer, SMALL_BUFFER_SIZE);
    memcpy(buffer, "A", 1);
    memcpy(buffer+1, my_id, ID_SIZE);
    memcpy(buffer+1+ID_SIZE, &key_verified, sizeof(int));
    send(sock, buffer, SMALL_BUFFER_SIZE, 0);
    close(sock);
}

int EnrolledDevice::verify_keys() {
    signature temp_s(IBE_obj->pairing);
    char st[] = "Smart Home Security: A distributed identity-based security protocol";

    //element_printf("temp_Kpub: %B\n", temp_Kpub);

    temp_s = IBE_obj->sign(st, my_Q, temp_D, sizeof(st));
    if(IBE_obj->sign_verify(st, &temp_s, my_Q, temp_Kpub, sizeof(st)))
        return 1;
    return 0;
}

void EnrolledDevice::receive_broadcast9() {
    int listeningSocket = socket(PF_INET, SOCK_DGRAM, 0);
    int broadcast = 1;
    if (listeningSocket <= 0) {
        perror("Error: listenForPackets - socket() failed.");
        return;
    }
    if (setsockopt(listeningSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &broadcast, sizeof broadcast) == -1) {
        perror("Error: listenForPackets - setsockopt failed");
        close(listeningSocket);
        return;
    }
    struct sockaddr_in sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(BROADCAST_PORT);
    sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    int status = bind(listeningSocket, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (status == -1) {
        close(listeningSocket);
        perror("Error: listenForPackets - bind() failed.");
        return;
    }
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    struct sockaddr_in receiveSockaddr;
    socklen_t receiveSockaddrLen = sizeof(receiveSockaddr);
    printf("Waiting for broadcast6 on port UDP:: %u\n",  BROADCAST_PORT);

    int recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE) {

         //recBytes += read(server_socket , buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
        recBytes += recvfrom(listeningSocket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes, 0, (struct sockaddr *)&receiveSockaddr, &receiveSockaddrLen);
        cout << "recBytes=" << recBytes << "/" << SMALL_BUFFER_SIZE << endl;
    }
    if (recBytes < 0) perror("ERROR while reading the db version");

    //int result = recvfrom(listeningSocket, buffer, SMALL_BUFFER_SIZE, 0, (struct sockaddr *)&receiveSockaddr, &receiveSockaddrLen);

    if(buffer[0] != '9') {
        cout << "at receive_broadcast9" << endl;
        abort();
    }
}

int EnrolledDevice::get_id_index(char* t_id) {
    int index = -1;
    for (int i=0; i<no_of_dev; i++)
        if (memcmp(id[i], t_id, 7) == 0)
            index = i;
    return index;
}

void EnrolledDevice::Compute_Network_Public_Key(element_t *t_sp){
    element_set0(temp_Kpub);
    for (int i=0;i<no_of_dev; i++)
    {
        element_add(temp_Kpub, temp_Kpub, t_sp[i]);
    }
}

void EnrolledDevice::Compute_Private_Key(element_t *t_sq){
    element_set0(temp_D);
    for (int i=0;i<no_of_dev; i++) {
        //element_printf("t_sq[%d]: %B\n", i, t_sq[i]);
        element_add(temp_D, temp_D, t_sq[i]);
    }
}

bool EnrolledDevice::Com_verify(element_t t_sp, element_t t_r, element_t t_com){
    element_t aux;
    element_init_G1(aux, IBE_obj->pairing);
    element_mul_zn(aux, IBE_obj->R, t_r);
    element_add(aux, aux, t_sp);
    return (!element_cmp(aux, t_com));
}
