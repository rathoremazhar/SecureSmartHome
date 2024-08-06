
/* 
 * File:   Admin.cpp
 * Author: muhammad
 * 
 * Created on January 20, 2019, 5:30 PM
 */

#include <unistd.h> 
#include <stdlib.h>
#include <stdio.h>
#include <cstring>
#include <thread> 
#include <iostream>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <netdb.h>
#include <sys/time.h>
#include <fstream>

#include "Admin.hpp"
#include "signature.hpp"
#include "symmetricCrypto.hpp"

using namespace std;

Admin::Admin() {
    //File for time storage
    myfile.open ("Time-Log-Admin.txt");
    //////////

    int i;
    no_of_dev=0;
    memcpy(my_id,"AdminPC", ID_SIZE); 
    memcpy(id[no_of_dev],"AdminPC", ID_SIZE); //id[0][ID_SIZE]="AdminPC";
    no_of_dev++;
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

    gettimeofday(&basic_op_start,NULL);
    element_from_hash(Q[0], id[0], ID_SIZE);
    gettimeofday(&basic_op_end,NULL);
    myfile << "MaptoPoint: " << print_time(&basic_op_start, &basic_op_end) << endl;

    element_set(my_Q, Q[0]);

    element_random(s);

    gettimeofday(&basic_op_start,NULL);
    element_mul_zn(IBE_obj.K, IBE_obj.P, s); //initialize Public key K with admin s.p
    gettimeofday(&basic_op_end,NULL);
    myfile << "IBE Element Multiplication time: " << print_time(&basic_op_start, &basic_op_end) << endl;

    element_set0(D);
    element_mul_zn(D, my_Q, s); //initial vprivate key.
    // element_printf("My Q: %B\n", my_Q);
    // element_printf("My Q: %B\n", Q[0]);
    // element_printf("My S: %B\n", s);
    if (!seed_prng()) /* seed PRNG */
    {
        printf ( " Fatal Error ! Unable to seed the PRNG !\n " );
        abort ();
    }
    RAND_bytes(iv, 16); //Genrate Vector for IV for every device for symetric encryption
}

Admin::Admin(const Admin& orig) {
}

void Admin::start_Server(string server_ip, int server_port, int t_commPort) {
    int server_fd, new_socket, valread, prev_valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    int addrlen = sizeof(address); 
    strcpy(list_ip[0], server_ip.c_str());
    list_ports[0] = server_port;
    list_comm_ports[0] = t_commPort;

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
    address.sin_port = htons(server_port); 
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
    printf("Waiting for client...\n");
    thread newClientThread[MAX_DEV];
    thread enrolledClientThread[MAX_DEV];
    thread keyExchangeThread[MAX_DEV];
    int noNewClients = 0;
    int noEnrolledClients = 0;
    int noKeyExchanges = 0;
    while(1) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        char buffer[SMALL_BUFFER_SIZE];
        bzero(buffer, SMALL_BUFFER_SIZE);

        size_t recBytes = 0;
        while (recBytes<SMALL_BUFFER_SIZE)
            recBytes += read(new_socket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
        if (recBytes < 0) perror("ERROR reading socket");

        //int valread = read(new_socket, buffer, SMALL_BUFFER_SIZE);
        char buffer2[SMALL_BUFFER_SIZE];
        bzero(buffer2, SMALL_BUFFER_SIZE);
        memcpy(buffer2, buffer, SMALL_BUFFER_SIZE);

        if (new_socket < 0) perror("ERROR on accept");
        if(buffer[0] == '1') {
            printf("receiving message 1...\n"); 
            newClientThread[noNewClients] = thread(&Admin::serve_New_Client, this, new_socket, buffer2);
            noNewClients++;
        }
        else if(buffer[0] == 'A'){
            printf("receiving message A...\n"); 
            enrolledClientThread[noEnrolledClients] = thread(&Admin::process_messageA, this, buffer2);
            noEnrolledClients++;
        }
        else if(buffer[0] == 'K'){
            printf("receiving message K...\n"); 
            keyExchangeThread[noKeyExchanges] = thread(&Admin::Receive_Session_key_Exchange, this, new_socket, buffer2);
            noKeyExchanges++;
        }
    }
    close(server_fd);
    myfile.close();
}

void Admin::Receive_Session_key_Exchange(int client_socket, char* buffer) {
    int remoteDeviceIndex = get_id_index(buffer+1);
    unsigned char TK[256];
    int j;
    unsigned char temp_skey[256];
    ctx = EVP_CIPHER_CTX_new();
    element_t aux_gt, aux_g1, aux_R, my_r, rec_rp, my_R, rec_R;

    element_init_GT(aux_gt, IBE_obj.pairing);
    element_init_G1(aux_g1, IBE_obj.pairing);
    element_init_Zr(my_r, IBE_obj.pairing);
    element_init_G1(rec_rp, IBE_obj.pairing);
    element_init_Zr(aux_R, IBE_obj.pairing);
    element_init_Zr(my_R, IBE_obj.pairing);
    element_init_Zr(rec_R, IBE_obj.pairing);

    gettimeofday(&basic_op_start,NULL);
    pairing_apply(aux_gt, Q[remoteDeviceIndex], D, IBE_obj.pairing);
    gettimeofday(&basic_op_end,NULL);
    myfile << "Bilinear Mapping time: " << print_time(&basic_op_start, &basic_op_end) << endl;

    element_to_bytes(TK, aux_gt);
    symmetricCrypto symmCrypt_obj;
    EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc(), NULL, TK, iv);

    gettimeofday(&op_start,NULL);
    unsigned char* s_pt = symmCrypt_obj.sdecrypt (ctx, (unsigned char*)buffer+1+ID_SIZE, 272);
    gettimeofday(&op_end,NULL);
    myfile << "Symetric Decryption (256bytes) Start: " << print_time(&op_start, &op_end) << endl;
    element_random(my_r);
    element_from_bytes(rec_rp, s_pt);
    element_mul_zn(aux_g1, rec_rp, my_r); // K = rj.ri.P
    element_to_bytes(temp_skey, aux_g1);
    //K1 recieved/////////

    element_mul_zn(aux_g1, IBE_obj.P, my_r); // rj.P
    element_to_bytes((unsigned char*)buffer, aux_g1); //rj.P
    EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc() , NULL , TK , iv);

    gettimeofday(&op_start,NULL);
    unsigned char* s_ct1 = symmCrypt_obj.sencrypt(ctx, (unsigned char*)buffer, 256, &j); //j=272
    gettimeofday(&op_end,NULL);
    myfile << "Symetric Encryption (256bytes) Start: " << print_time(&op_start, &op_end) << endl;

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

    gettimeofday(&basic_op_start,NULL);
    if (element_cmp(aux_R, my_R))
        perror("ERROR rec_R and my_R are not the same");

    gettimeofday(&basic_op_end,NULL);
    myfile << "Comparing two IBC Elements: " << print_time(&basic_op_start, &basic_op_end) << endl;
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

void Admin::Send_Session_key_Exchange() {
    int remoteDeviceIndex = -1;
    cin >> remoteDeviceIndex;
    if (remoteDeviceIndex < 0)
        exit(1);
    int currentDeviceIndex = get_id_index(my_id);

    struct sockaddr_in address; 
    int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return; 
    } 
    memset(&serv_addr, '0', sizeof(serv_addr)); 
    serv_addr.sin_family = AF_INET; 
    serv_addr.sin_port = htons(list_comm_ports[remoteDeviceIndex]); 
    if(inet_pton(AF_INET, list_ip[remoteDeviceIndex], &serv_addr.sin_addr)<=0) 
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return; 
    } 
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        printf("\nConnection Failed \n"); 
        return; 
    } 
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    memcpy(buffer, "K", 1);
    memcpy(buffer, my_id, ID_SIZE);
    unsigned char TK[256];
    element_t aux_gt;
    element_t my_r;
    element_t aux_g1;
    element_init_GT(aux_gt, IBE_obj.pairing);
    element_init_Zr(my_r, IBE_obj.pairing);
    element_init_G1(aux_g1, IBE_obj.pairing);
    pairing_apply(aux_gt, Q[remoteDeviceIndex], D, IBE_obj.pairing);
    element_to_bytes(TK, aux_gt);
    element_random(my_r);
    element_mul_zn(aux_g1, IBE_obj.P, my_r); //initial vprivate key.
    element_printf("aux_gt: %B\n", aux_gt);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE, aux_g1);
    int j;
    ctx = EVP_CIPHER_CTX_new ();
    EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc() , NULL , TK , iv);
    //We need the +1 because it holds the terminating NULL character 
    symmetricCrypto symmCrypt_obj;
    unsigned char* s_ct = symmCrypt_obj.sencrypt(ctx, (unsigned char*)buffer+1+ID_SIZE, 256, &j); //j=272
    send(sock, buffer, SMALL_BUFFER_SIZE, 0); 
}

void Admin::serve_New_Client(int client_socket, char* buffer) {
    receive_message1(client_socket, buffer);
    printf("message 1 received...\n"); 
    send_message2(client_socket);
    printf("message 2 sent...\n");
    receive_message3(client_socket);
    printf("message 3 received...\n"); 
    send_message4p(client_socket);
    printf("message 4p sent...\n");
    send_message4i(client_socket);
    printf("message 4i sent...\n");
    receive_message5(client_socket);
    printf("message 5 received...\n");
    no_of_dev++;
    broadcast_message6();
    printf("broadcast 6 sent...\n");
    usleep(400000);
    broadcast_message7();
    printf("broadcast 7 sent...\n");
    receive_broadcasts7();
    printf("broadcasts 7 received...\n");
    //usleep(2000000);
    int i;
    cin >> i;
    exchange_newer_messages8();
    printf("messages 8 exchanged with all newer devices...\n");
    //keys are calculated after sending message 8
    Compute_Network_Public_Key(sP);
    Compute_Private_Key(sQ);
    if (!verify_keys()) {
        cout << "key calculated on the Admin is not verified!" << endl;
        //To be checked later!
        exit(1);
    }

    element_set(IBE_obj.K, temp_Kpub);
    element_set(D, temp_D);
    cout << "keys have been updated successfully!" << endl;
}

Admin::~Admin() {
}

void Admin::update_Gids() {
    struct timeval start; struct timeval end;
    for(int i=0; i<no_of_dev; i++) {
        gettimeofday(&start,NULL);
        element_pairing(G[i], Q[i], IBE_obj.K);
        gettimeofday(&end,NULL);
        printf("pairing Time: %f ms\n", print_time(&start, &end));   
    }
}

double Admin::print_time(struct timeval *start, struct timeval *end) {
    double usec;
    usec = (end->tv_sec*1000000 + end->tv_usec) - (start->tv_sec*1000000 +
        start->tv_usec);
    return usec/1000;
}

void Admin::receive_message1(int client_socket, char *buffer) {
    //cout << "buffer=" << buffer << endl;
    if(buffer[0] != '1'){ //its request message
        //cout << "buffer=" << buffer << endl;
        abort();
    }
    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    int res = getpeername(client_socket, (struct sockaddr *)&addr, &addr_size);
    char* ip = inet_ntoa(addr.sin_addr);
    int port;
    memcpy(&port, buffer+8, sizeof(int));
    list_ports[no_of_dev] = port;
    memcpy(&port, buffer+8+sizeof(int), sizeof(int));
    list_comm_ports[no_of_dev] = port;
    strcpy(list_ip[no_of_dev], ip);
    memcpy(id[no_of_dev],buffer + 1, ID_SIZE);
    element_from_hash(Q[no_of_dev], id[no_of_dev], ID_SIZE);
    // if (no_of_dev == 2) {
    // //     element_t aux1;
    // //     element_init_G1(aux1, IBE_obj->pairing);
    // //     element_mul_zn(aux1, Q[0], s); //aux1 = sP
    // //     element_printf("q0s1: %B\n", aux1);

    // //     element_t aux2;
    // //     element_init_G1(aux2, IBE_obj->pairing);
    // //     element_mul_zn(aux2, Q[1], s); //aux1 = sP
    // //     element_printf("Q[1]: %B\n", Q[1]);
    // //     element_printf("s1: %B\n", s);
    // //     element_printf("q1s1: %B\n", aux2);

    // //     element_t aux4;
    // //     element_init_G1(aux4, IBE_obj->pairing);
    // //     element_mul_zn(aux4, my_Q, s); //aux1 = sP
    // //     element_printf("my_Q: %B\n", my_Q);
    // //     element_printf("s1: %B\n", s);
    // //     element_printf("q1s1: %B\n", aux4);

    // //     element_t aux3;
    // //     element_init_G1(aux3, IBE_obj->pairing);
    // //     element_mul_zn(aux3, Q[2], s); //aux1 = sP
    //    // element_printf("q2: %B\n", Q[2]);
    // }
}

void Admin::send_message2(int client_socket) {
    char buffer[SMALL_BUFFER_SIZE];
    bzero(buffer, SMALL_BUFFER_SIZE);
    RAND_bytes(pwd, 32);
    memcpy(buffer,"2", 1);
    memcpy(buffer+1, pwd, 32);
    memcpy(buffer+1+32, iv, 16);
    send(client_socket, buffer, 1024, 0);
}

int Admin::seed_prng() {

    return RAND_load_file("/dev/urandom", 32);
}

void Admin::receive_message3(int client_socket) {
    char buffer[SMALL_BUFFER_SIZE];
    bzero(buffer, SMALL_BUFFER_SIZE);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    memcpy(buffer, pwd, 32);
    memcpy(buffer+32, iv, 16);
    SHA256((unsigned char*)buffer, 48, hash);
    bzero(buffer, SMALL_BUFFER_SIZE);
    size_t recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE)
        recBytes += read(client_socket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR reading socket");
    //int valread = read(client_socket, buffer, SMALL_BUFFER_SIZE);
    if(buffer[0] != '3') //its request message
        abort();
    if(memcmp(hash, buffer+1, 32)!=0) // Verify Hash
    {
        printf("Error: PWD hash message change during transmission\n");
        exit(1);
    }
}

void Admin::send_message4p(int client_socket) {
    char buffer[BUFFER_SIZE];
    bzero(buffer, BUFFER_SIZE);
    
    int j=0;
    memcpy(buffer,"4", 1);
    memcpy(buffer+1,"p", 1);
    element_to_bytes((unsigned char*)buffer+2, IBE_obj.P);
    element_to_bytes((unsigned char*)buffer+2+256, IBE_obj.K);
    element_to_bytes((unsigned char*)buffer+2+256+256, IBE_obj.R);
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc() , NULL , pwd , iv);
    //We need the +1 because it holds the terminating NULL character 
    symmetricCrypto symmCrypt_obj;
    unsigned char* s_ct = symmCrypt_obj.sencrypt(ctx, (unsigned char*)buffer+2, 512+256, &j);
    memcpy(buffer+2, s_ct, 528+256);
    send(client_socket, buffer, BUFFER_SIZE , 0 );
}

void Admin::send_message4i(int client_socket) {
    char buffer[SMALL_BUFFER_SIZE];
    bzero(buffer, SMALL_BUFFER_SIZE);
    memcpy(buffer,"4", 1);
    memcpy(buffer+1,"i", 1);

     memcpy(buffer+2, &no_of_dev, sizeof(int));
    memcpy(buffer+2+sizeof(int), id, no_of_dev*ID_SIZE);

    memcpy(buffer+2+sizeof(int)+(no_of_dev*ID_SIZE), list_ip, IP_ADDRESS_SIZE*no_of_dev);
    memcpy(buffer+2+sizeof(int)+(no_of_dev*ID_SIZE)+(IP_ADDRESS_SIZE*no_of_dev), list_ports, sizeof(int)*no_of_dev);
    memcpy(buffer+2+sizeof(int)+(no_of_dev*ID_SIZE)+(IP_ADDRESS_SIZE*no_of_dev)+sizeof(int)*no_of_dev, list_comm_ports, sizeof(int)*no_of_dev);
    send(client_socket, buffer, SMALL_BUFFER_SIZE , 0 );
}

void Admin::receive_message5(int client_socket) {
    char buffer[SMALL_BUFFER_SIZE];
    char temp_buffer[SMALL_BUFFER_SIZE];
    unsigned char* databytes = (unsigned char *)malloc(sizeof(unsigned char) * 256);
    unsigned char hash[SHA256_DIGEST_LENGTH];

    bzero(buffer, SMALL_BUFFER_SIZE);
    bzero(temp_buffer, SMALL_BUFFER_SIZE);
    memcpy(temp_buffer, pwd, 32);
    memcpy(temp_buffer+32, iv, 16);

    size_t recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE)
        recBytes += read(client_socket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR reading socket");
    
    if(buffer[0] != '5') //its request message
        abort();
    ctx = EVP_CIPHER_CTX_new ();
    EVP_DecryptInit_ex (ctx , EVP_aes_256_cbc () , NULL , pwd , iv );
    symmetricCrypto symmCrypt_obj;
    unsigned char* s_pt = symmCrypt_obj.sdecrypt (ctx, (unsigned char*)buffer+1, 272);
    element_from_bytes(COM[no_of_dev], s_pt+ID_SIZE);
}

void Admin::broadcast_message6() {
    char buffer[SMALL_BUFFER_SIZE];
    bzero(buffer, SMALL_BUFFER_SIZE);
    signature temp_s(IBE_obj.pairing);
    memcpy(buffer,"6", 1);
    memcpy(buffer+1, &id[no_of_dev-1], ID_SIZE);
    cout<< "New Device ID :" << id[no_of_dev-1] <<endl;
    memcpy(buffer+1+ID_SIZE, &list_ip[no_of_dev-1], IP_ADDRESS_SIZE);
    memcpy(buffer+1+ID_SIZE+IP_ADDRESS_SIZE, &list_ports[no_of_dev-1], sizeof(int));
    memcpy(buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int), &list_comm_ports[no_of_dev-1], sizeof(int));

    element_to_bytes((unsigned char *)buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int), COM[no_of_dev-1]);
    temp_s = IBE_obj.sign(buffer+1, Q[0], D, ID_SIZE+IP_ADDRESS_SIZE+sizeof(int)+256);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int)+256, temp_s.U);
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int)+256+256, temp_s.V);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock<0) {
        printf("Cannot open sock \n");
        exit(1);
    }
    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof broadcast) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        exit(1);
    }
    struct sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family = AF_INET;
    inet_pton(AF_INET, BROADCAST_ADDRESS.c_str(), &remoteAddr.sin_addr);
    remoteAddr.sin_port = htons(BROADCAST_PORT);
    int ret = sendto(sock, buffer, SMALL_BUFFER_SIZE, 0, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));
    if (ret < 0) {
        perror("Error: Could not open send broadcast.");
        close(sock);
        exit(1);
    }
    close(sock);
}

void Admin::broadcast_message7() {
    char buffer[SMALL_BUFFER_SIZE];
    bzero(buffer, SMALL_BUFFER_SIZE);
    unsigned char* databytes = (unsigned char *)malloc(sizeof(unsigned char) * 256);

    signature temp_s(IBE_obj.pairing);
    element_random(r);
    element_random(s);
    element_t aux1, aux2;
    element_init_G1(aux1, IBE_obj.pairing);
    element_init_G1(aux2, IBE_obj.pairing);

    gettimeofday(&op_start,NULL);
    element_mul_zn(aux1, IBE_obj.R, r);
    element_mul_zn(aux2, IBE_obj.P, s);
    element_add(my_COM, aux1, aux2);
    gettimeofday(&op_end,NULL);
    myfile << "IBC Commitment generation time: " << print_time(&op_start, &op_end) << endl;

    element_to_bytes(databytes, my_COM);
   
    memcpy(buffer, "7", 1);
    memcpy(buffer+1, my_id, ID_SIZE);
    memcpy(buffer+1+ID_SIZE, databytes, 256);


    gettimeofday(&op_start,NULL);
    temp_s = IBE_obj.sign(buffer+1, my_Q, D, ID_SIZE+256);
    gettimeofday(&op_end,NULL);
    myfile << "ibc signature (256bytes) time: " << print_time(&op_start, &op_end) << endl;


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

    cout << "broadcast_message7:broadcast_message7 sent"<< endl;
    struct timeval now;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
    if(rc<0) {
        printf("Cannot send data %d \n", i-1);
        exit(1);
    }
    close(sd);
}

void Admin::receive_broadcasts7() {
    if (no_of_dev == 2)
        //usleep(1000000);
    if (no_of_dev > 2) {
        int rec_no_coms;
        thread tid[no_of_dev-2];
        for (rec_no_coms=0; rec_no_coms<no_of_dev-2; rec_no_coms++) {
            tid[rec_no_coms] = thread(&Admin::process_broadcast7, this);
        }
        for (rec_no_coms=0; rec_no_coms<no_of_dev-2; rec_no_coms++) {
            tid[rec_no_coms].join();
        }
    }
}

void Admin::process_broadcast7() {
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

    cout << "process_broadcast7:process_broadcast7 received" << endl;
    struct timeval now;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;

    if(buffer[0] != '7')
        abort();
    unsigned char tempbuff[256];
    signature temp_s(IBE_obj.pairing);
    memcpy(tempbuff, buffer+1+ID_SIZE+256, 256);
    element_from_bytes(temp_s.U, tempbuff);
    memcpy(tempbuff, buffer+1+ID_SIZE+256+256, 256);
    element_from_bytes(temp_s.V, tempbuff);
    int device_id = get_id_index(buffer+1);

    gettimeofday(&op_start,NULL);
    if(!IBE_obj.sign_verify((char *)buffer+1, &temp_s, Q[device_id], ID_SIZE+256))
    {
        printf("-------Commitment from admin is not verified\n");
        exit(1);
    }
    gettimeofday(&op_end,NULL);
    myfile << "IBC signature Verification time: " << print_time(&op_start, &op_end) << endl;

    element_from_bytes(COM[device_id], (unsigned char*)buffer+1+ID_SIZE);
}

void Admin::exchange_newer_messages8() {
    struct timeval now;
    int my_index = get_id_index(my_id);
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    //int socketsList[no_of_dev];
    // for (int device_index=my_index+1; device_index<no_of_dev; device_index++) {
    //     if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    //     { 
    //         printf("\n Socket creation error \n"); 
    //         exit(1);
    //     } 
    //     memset(&serv_addr, '0', sizeof(serv_addr)); 
    //     serv_addr.sin_family = AF_INET; 
    //     serv_addr.sin_port = htons(list_ports[device_index]); 

    //     cout << "exchange_newer_messages8: opening socket with device " << device_index << " : " << list_ip[device_index] << ":" << list_ports[device_index] << endl;
    // gettimeofday(&now,NULL);
    // cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;

    //     if(inet_pton(AF_INET, list_ip[device_index], &serv_addr.sin_addr)<=0) 
    //     { 
    //         printf("\nInvalid address/ Address not supported \n"); 
    //         exit(1);
    //     } 

    //     if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
    //     { 
    //         printf("\nConnection Failed \n"); 
    //         exit(1);
    //     } 
    //     socketsList[device_index] = sock;
    // }

    element_t aux1, aux2, t_r;
    element_init_Zr(t_r, IBE_obj.pairing);
    element_init_G1(aux1, IBE_obj.pairing);
    element_init_G1(aux2, IBE_obj.pairing);
    element_set0(aux1);
    element_mul_zn(aux1, IBE_obj.P, s); //aux1 = sP


    
    // element_printf("Adminr: %B\n", s);
    // element_printf("Adminr: %B\n", IBE_obj.P);
    // element_printf("Adminr: %B\n", r);
    // element_printf("AdminSP1: %B\n", aux1);
    // element_printf("Admin Side COM: %B\n", my_COM);

    element_mul_zn(aux2, my_Q, s); //aux1 = sP
    element_set(sP[my_index], aux1);
    element_set(sQ[my_index], aux2);
    unsigned char tempbuff[256];
    signature temp_s(IBE_obj.pairing);
    int device_id = 0;
    char buffer[BUFFER_SIZE];
    for (int device_index=my_index+1; device_index<no_of_dev; device_index++) {
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
        { 
            printf("\n Socket creation error \n"); 
            exit(1);
        } 
        memset(&serv_addr, '0', sizeof(serv_addr)); 
        serv_addr.sin_family = AF_INET; 
        serv_addr.sin_port = htons(list_ports[device_index]); 

        cout << "exchange_newer_messages8: opening socket with device " << device_index << " : " << list_ip[device_index] << ":" << list_ports[device_index] << endl;
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
        //sending secret share values to the device
        bzero(buffer, BUFFER_SIZE);
        element_set0(aux2);
        element_mul_zn(aux1, IBE_obj.P, s); //aux1 = sP
        element_mul_zn(aux2, Q[device_index], s);   //aux2= sQ
        memcpy(buffer, "8", 1);
        memcpy(buffer+1, my_id, ID_SIZE);
        element_to_bytes((unsigned char*)buffer+1+ID_SIZE, r);
        element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256, aux1);
        // element_printf("AdminSP2: %B\n", aux1);
        // element_printf("s: %B\n", s);
        // element_printf("IBE_obj.P: %B\n", IBE_obj.P);
        element_to_bytes((unsigned char*)buffer+1+ID_SIZE+256+256, aux2);
    cout << "exchange_newer_messages8: sending message 8 to device " << device_index << " : " << list_ip[device_index] << ":" << list_ports[device_index] << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
        send(sock, buffer, BUFFER_SIZE, 0);
    cout << "exchange_newer_messages8: message 8 sent to" << device_index << " : " << list_ip[device_index] << ":" << list_ports[device_index] << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;

        //receiving secret share values to the device
        bzero(buffer, BUFFER_SIZE);

        size_t recBytes = 0;
        while (recBytes<BUFFER_SIZE)
            recBytes += read(sock, buffer+recBytes, BUFFER_SIZE-recBytes);
        if (recBytes < 0) perror("ERROR reading socket");
    cout << "exchange_newer_messages8: message 8 received from" << device_index << " : " << list_ip[device_index] << ":" << list_ports[device_index] << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;

        //valread = read(sock, buffer, BUFFER_SIZE);
        if(buffer[0]!='8') //its parameters message
            exit(1);
        device_id = get_id_index(buffer+1);

        element_from_bytes(t_r, (unsigned char*)buffer+1+ID_SIZE);
        element_from_bytes(aux1, (unsigned char*)buffer+1+ID_SIZE+256);
        element_from_bytes(aux2, (unsigned char*)buffer+1+ID_SIZE+256+256);
        
        gettimeofday(&op_start,NULL);
        if (!Com_verify(aux1, t_r, COM[device_id])) {
            cout << "-------Commitment from device " << id[device_id] << " is not verified" << endl;
            exit(1);
        }
         gettimeofday(&op_end,NULL);
         myfile << "IBC Commitment Verification time: " << print_time(&op_start, &op_end) << endl;

        element_set(sP[device_id], aux1);
        element_set(sQ[device_id], aux2);
    }
}

void Admin::process_messageA(char* buffer) {
    int keyVerified = 0;
    char device_id[ID_SIZE];
    memcpy(device_id, buffer+1, ID_SIZE);
    memcpy(&keyVerified, buffer+1+ID_SIZE, sizeof(int));

    if (!keyVerified) {
        cout << "key from device: " << device_id << " not verified!" << endl;
        //To be checked later!
        exit(1);
    }
    else {
        cout << "key from device: " << device_id << " verified." << endl;
        noVerifiedKeys++;
    }
    if (noVerifiedKeys == no_of_dev-1) {
        allKeysVerified = true;
        cout << "all keys have been verified" << endl;
        broadcast_message9();
        cout << "broadcast_message9 sent" << endl;
        //Send_Session_key_Exchange();
        noVerifiedKeys = 0;
        allKeysVerified = false;
    }
}

void Admin::broadcast_message9() {
    char buffer[SMALL_BUFFER_SIZE];
    bzero(buffer, SMALL_BUFFER_SIZE);
    signature temp_s(IBE_obj.pairing);
    memcpy(buffer,"9", 1);
    char ack[] = "key generation set sussfully";
    memcpy(buffer+1, ack, sizeof(ack));
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock<0) {
        printf("Cannot open sock \n");
        exit(1);
    }
    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof broadcast) == -1) {
        perror("setsockopt (SO_BROADCAST)");
        exit(1);
    }
    struct sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family = AF_INET;
    inet_pton(AF_INET, BROADCAST_ADDRESS.c_str(), &remoteAddr.sin_addr);
    remoteAddr.sin_port = htons(BROADCAST_PORT);
    int ret = sendto(sock, buffer, SMALL_BUFFER_SIZE, 0, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr));
    if (ret < 0) {
        perror("Error: Could not open send broadcast.");
        close(sock);
        exit(1);
    }
    close(sock);
}

bool Admin::verify_keys() {
    signature temp_s(IBE_obj.pairing);
    char st[] = "Smart Home Security: A distributed identity-based security protocol";

    // element_printf("temp_Kpub: %B\n", temp_Kpub);

    temp_s = IBE_obj.sign(st, my_Q, temp_D, sizeof(st));
    if(IBE_obj.sign_verify(st, &temp_s, my_Q, temp_Kpub, sizeof(st)))
        return true;
    return false;
}

int Admin::get_id_index(char* t_id) {
    int index = -1;
    for (int i=0; i<no_of_dev; i++)
        if (memcmp(id[i], t_id, 7) == 0)
            index = i;
    return index;
}

void Admin::Compute_Network_Public_Key(element_t *t_sp) {
    element_set0(temp_Kpub);
    for (int i=0;i<no_of_dev; i++)
    {
        gettimeofday(&basic_op_start,NULL);
        element_add(temp_Kpub, temp_Kpub, t_sp[i]);
        gettimeofday(&basic_op_end,NULL);
        myfile << "IBC Element Addition time: " << print_time(&basic_op_start, &basic_op_end) << endl;
        //element_printf("t_sp[i]: %B\n", t_sp[i]);
    }
}

void Admin::Compute_Private_Key(element_t *t_sq){
    element_set0(temp_D);
    for (int i=0;i<no_of_dev; i++)
    {
        //element_printf("t_sq[%d]: %B\n", i, t_sq[i]);
        element_add(temp_D, temp_D, t_sq[i]);
    }
}

bool Admin::Com_verify(element_t t_sp,element_t t_r,element_t t_com){
    element_t aux;
    element_init_G1(aux, IBE_obj.pairing);
    element_mul_zn(aux, IBE_obj.R, t_r);
    element_add(aux, aux, t_sp);
    return (!element_cmp(aux, t_com));
}
