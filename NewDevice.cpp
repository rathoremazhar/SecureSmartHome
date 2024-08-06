
/* 
 * File:   NewDevice.cpp
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
#include <sys/time.h>

#include "NewDevice.hpp"
#include "symmetricCrypto.hpp"
#include "EnrolledDevice.hpp"

using namespace std;

NewDevice::NewDevice(std::string n_id) {

    //File for time storage
    myfile.open ("Time-Log-Device.txt");
    //////////

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

    gettimeofday(&op_start,NULL);
    element_from_hash(Q[0], id[0], ID_SIZE);
    gettimeofday(&op_end,NULL);
    myfile << "MaptoPoint time: " << print_time(&op_start, &op_end) << endl;

    element_from_hash(my_Q, my_id, ID_SIZE);
    
    element_random(s);
    element_set0(D);
    gettimeofday(&basic_op_start,NULL);
    element_mul_zn(D, my_Q, s); //initial private key.
    gettimeofday(&basic_op_end,NULL);
    myfile << "IBC Element Multiplication time: " << print_time(&basic_op_start, &basic_op_end) << endl;

    // element_printf("My Q-Device: %B\n", my_Q);
    // element_printf("My S-Device: %B\n", s);
    RAND_bytes(iv, 16); //Genrate Vector for IV for every device for symetric encryption

    stamp_ptr = new signature(IBE_obj.pairing);
}

int NewDevice::start_Device(string server_ip, int server_port, int t_local_port, int t_local_comm_port) {
    printf("Connecting to the server...\n"); 
    local_port = t_local_port;
    local_comm_port = t_local_comm_port;
    struct sockaddr_in address; 
    int sock = 0, valread; 
    struct sockaddr_in serv_addr; 
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

    gettimeofday(&proto_start,NULL);
    gettimeofday(&phase_start,NULL);
    send_message1(sock);
    printf("message 1 sent...\n"); 
    receive_message2(sock);
    printf("message 2 received...\n"); 
    send_message3(sock);
    printf("message 3 sent...\n"); 
    receive_message4p(sock);
    printf("message 4p received...\n"); 
    receive_message4i(sock);
    printf("message 4i received...\n"); 
    gettimeofday(&phase_end,NULL);
    myfile << "Registeration Phase time: " << print_time(&phase_start, &phase_end) << endl;

    send_message5(sock);
    gettimeofday(&phase_start,NULL);
    printf("message 5 sent...\n");
    no_of_dev++;
    //thread t6 = thread(&NewDevice::receive_broadcast6, this);
    receive_broadcast6();
    printf("broadcast 6 received...\n");
    receive_broadcasts7();
    printf("broadcast 7 received...\n");
    exchange_older_messages8();
    printf("messages 8 exchanged with all older devices...\n");
    //keys are calculated after sending message 8
    Compute_Network_Public_Key(sP);
    Compute_Private_Key(sQ);

    send_messageA();
    printf("message A sent...\n"); 
    receive_broadcast9();
    printf("broadcast9 recieved!\n"); 
    gettimeofday(&phase_end,NULL);
    myfile << "Phase-2 time: " << print_time(&phase_start, &phase_end) << endl;

    element_set(IBE_obj.K, temp_Kpub);
    element_set(D, temp_D);
    cout << "keys have been updated successfully!" << endl;

    //Send_Session_key_Exchange(0);// key sxchage with particular device with index 0
    gettimeofday(&phase_start,NULL);
    //TODO uncomment
    //Send_Session_key_Exchange_all_devices();
    gettimeofday(&phase_end,NULL);
    myfile << "Phase-3 session key exchange time: " << print_time(&phase_start, &phase_end) << endl;

    gettimeofday(&proto_end,NULL);
    myfile << "Overall Protocol Time: " << print_time(&proto_start, &proto_end) << endl;

    EnrolledDevice my_self;
    my_self.set_Parameters(&IBE_obj, no_of_dev, my_id, id, list_ip, list_ports, local_port, my_Q, D, Q, iv, list_comm_ports, local_comm_port);
    my_self.start_Device();

    myfile.close();
    return 0; 
}

NewDevice::NewDevice(const NewDevice& orig) {
}

NewDevice::~NewDevice() {
}

void NewDevice::update_Gids(){
    for(int i=0; i<no_of_dev; i++)
        element_pairing(G[i], Q[i], IBE_obj.K);
}

void NewDevice::Send_Session_key_Exchange_all_devices() {
    for (int i=0; i<no_of_dev; i++)
        if (i != get_id_index(my_id))
            Send_Session_key_Exchange(i);
}

void NewDevice::Send_Session_key_Exchange(int remoteDeviceIndex) {
    cout << "Send_Session_key_Exchange: sending Session_key_Exchange to device: " << remoteDeviceIndex << " no_of_dev=" << no_of_dev << endl;
    if (remoteDeviceIndex >= no_of_dev)
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
    memcpy(buffer+1, my_id, ID_SIZE);

    unsigned char TK[256];
    unsigned char temp_skey[256];
    element_t aux_gt, my_r, rec_rp, aux_R, rec_R, my_R, aux_g1;
    element_init_GT(aux_gt, IBE_obj.pairing);
    element_init_Zr(my_r, IBE_obj.pairing);
    element_init_Zr(rec_R, IBE_obj.pairing);
    element_init_Zr(my_R, IBE_obj.pairing);
    element_init_Zr(aux_R, IBE_obj.pairing);
    element_init_G1(aux_g1, IBE_obj.pairing);
    element_init_G1(rec_rp, IBE_obj.pairing);

    gettimeofday(&basic_op_start,NULL);
    pairing_apply(aux_gt, Q[remoteDeviceIndex], D, IBE_obj.pairing);
    gettimeofday(&basic_op_end,NULL);
    myfile << "Bilinear Mapping time: " << print_time(&basic_op_start, &basic_op_end) << endl;

    element_to_bytes(TK, aux_gt);
    element_random(my_r);
    element_mul_zn(aux_g1, IBE_obj.P, my_r); //initial vprivate key.
    
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE, aux_g1);
    int j;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc() , NULL , TK , iv);

    symmetricCrypto symmCrypt_obj;

    gettimeofday(&op_start,NULL);
    unsigned char* s_ct = symmCrypt_obj.sencrypt(ctx, (unsigned char*)buffer+1+ID_SIZE, 256, &j); //j=272
    gettimeofday(&op_end,NULL);
    myfile << "Symetric Encryption time: " << print_time(&op_start, &op_end) << endl;

    memcpy(buffer+1+ID_SIZE, s_ct, 272);
    //cout << "sending K to: " << list_ip[remoteDeviceIndex] << ":" << list_comm_ports[remoteDeviceIndex] << endl;
    send(sock, buffer, SMALL_BUFFER_SIZE, 0); 
    //K1 sent ///////////////////////

    bzero(buffer, SMALL_BUFFER_SIZE);
    size_t recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE)
        recBytes += read(sock, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR reading socket");
    EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc(), NULL, TK, iv);

    gettimeofday(&op_start,NULL);    
    unsigned char* s_pt1 = symmCrypt_obj.sdecrypt(ctx, (unsigned char*)buffer, 272);
    gettimeofday(&op_end,NULL);
    myfile << "Symetric Decryption time: " << print_time(&op_start, &op_end) << endl;

    element_from_bytes(rec_rp, s_pt1);
    element_mul_zn(aux_g1, rec_rp, my_r);
    element_to_bytes(temp_skey, aux_g1);
    EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc(), NULL, temp_skey, iv);    
    unsigned char* s_pt2 = symmCrypt_obj.sdecrypt (ctx, (unsigned char*)buffer+272, 272);
    element_from_bytes(rec_R, s_pt2);
    //K2 received/////////////////////////

    bzero(buffer, SMALL_BUFFER_SIZE);
    element_random(my_R);
    element_to_bytes((unsigned char*)buffer, my_R);
    memcpy(buffer+256, s_pt2, 256);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc() , NULL , temp_skey , iv);
    s_ct = symmCrypt_obj.sencrypt(ctx, (unsigned char*)buffer, 256+256, &j); //j=528
    memcpy(buffer, s_ct, 528);
    send(sock, buffer, SMALL_BUFFER_SIZE, 0); 
    //K3 sent//////////////////////////////
    
    bzero(buffer, SMALL_BUFFER_SIZE);
    recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE)
        recBytes += read(sock, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR reading socket");
    EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc(), NULL, temp_skey, iv);
    s_pt1 = symmCrypt_obj.sdecrypt(ctx, (unsigned char*)buffer, 272);
    element_from_bytes(aux_R, s_pt1);

    gettimeofday(&op_start,NULL);
    if (element_cmp(aux_R, my_R))
        perror("ERROR rec_R and my_R are not the same");
    gettimeofday(&op_end,NULL);
    myfile << "Element Compare time: " << print_time(&op_start, &op_end) << endl;
    //K4 received//////////////////////////

    memcpy(s_key[remoteDeviceIndex], temp_skey, 256);
    cout << "Session_key_Exchange successfully sent to device index:" << remoteDeviceIndex << endl;
}

void NewDevice::Send_Session_key_Exchange() {
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
    memcpy(buffer+1, my_id, ID_SIZE);

    unsigned char TK[256];
    unsigned char temp_skey[256];
    element_t aux_gt, my_r, rec_rp, aux_R, rec_R, my_R, aux_g1;
    element_init_GT(aux_gt, IBE_obj.pairing);
    element_init_Zr(my_r, IBE_obj.pairing);
    element_init_Zr(rec_R, IBE_obj.pairing);
    element_init_Zr(my_R, IBE_obj.pairing);
    element_init_Zr(aux_R, IBE_obj.pairing);
    element_init_G1(aux_g1, IBE_obj.pairing);
    element_init_G1(rec_rp, IBE_obj.pairing);
    pairing_apply(aux_gt, Q[remoteDeviceIndex], D, IBE_obj.pairing);

    element_to_bytes(TK, aux_gt);
    element_random(my_r);
    element_mul_zn(aux_g1, IBE_obj.P, my_r); //initial vprivate key.
    
    element_to_bytes((unsigned char*)buffer+1+ID_SIZE, aux_g1);
    int j;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc() , NULL , TK , iv);

    symmetricCrypto symmCrypt_obj;
    unsigned char* s_ct = symmCrypt_obj.sencrypt(ctx, (unsigned char*)buffer+1+ID_SIZE, 256, &j); //j=272
    memcpy(buffer+1+ID_SIZE, s_ct, 272);
    //cout << "sending K to: " << list_ip[remoteDeviceIndex] << ":" << list_comm_ports[remoteDeviceIndex] << endl;
    send(sock, buffer, SMALL_BUFFER_SIZE, 0); 
    //K1 sent ///////////////////////

    bzero(buffer, SMALL_BUFFER_SIZE);
    size_t recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE)
        recBytes += read(sock, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR reading socket");
    EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc(), NULL, TK, iv);
    unsigned char* s_pt1 = symmCrypt_obj.sdecrypt(ctx, (unsigned char*)buffer, 272);
    element_from_bytes(rec_rp, s_pt1);
    element_mul_zn(aux_g1, rec_rp, my_r);
    element_to_bytes(temp_skey, aux_g1);
    EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc(), NULL, temp_skey, iv);    
    unsigned char* s_pt2 = symmCrypt_obj.sdecrypt (ctx, (unsigned char*)buffer+272, 272);
    element_from_bytes(rec_R, s_pt2);
    //K2 received/////////////////////////

    bzero(buffer, SMALL_BUFFER_SIZE);
    element_random(my_R);
    element_to_bytes((unsigned char*)buffer, my_R);
    memcpy(buffer+256, s_pt2, 256);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc() , NULL , temp_skey , iv);
    s_ct = symmCrypt_obj.sencrypt(ctx, (unsigned char*)buffer, 256+256, &j); //j=528
    memcpy(buffer, s_ct, 528);
    send(sock, buffer, SMALL_BUFFER_SIZE, 0); 
    //K3 sent//////////////////////////////
    
    bzero(buffer, SMALL_BUFFER_SIZE);
    recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE)
        recBytes += read(sock, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR reading socket");
    EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc(), NULL, temp_skey, iv);
    s_pt1 = symmCrypt_obj.sdecrypt(ctx, (unsigned char*)buffer, 272);
    element_from_bytes(aux_R, s_pt1);
    if (element_cmp(aux_R, my_R))
        perror("ERROR rec_R and my_R are not the same");
    //K4 received//////////////////////////

    memcpy(s_key[remoteDeviceIndex], temp_skey, 256);
    cout << "Session_key_Exchange successfull" << endl;
}

void NewDevice::send_message1(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    memcpy(buffer,"1", 1);
    memcpy(buffer+1, my_id, ID_SIZE);
    memcpy(buffer+8, &local_port, sizeof(int));
    memcpy(buffer+8+sizeof(int), &local_comm_port, sizeof(int));
    send(server_socket, buffer, SMALL_BUFFER_SIZE, 0); 
}

void NewDevice::receive_message2(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);

    size_t recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE)
        recBytes += read(server_socket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR reading socket");

    //int valread = read(server_socket , buffer, SMALL_BUFFER_SIZE); 
    if(buffer[0] != '2') //its parameters message
        abort();
    memcpy(pwd, buffer+1, 32);
    memcpy(iv, buffer+1+32, 16);
}

void NewDevice::send_message3(int server_socket) {
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

void NewDevice::receive_message4p(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * BUFFER_SIZE);
    bzero(buffer, BUFFER_SIZE);

    int recBytes = 0;
    while (recBytes<BUFFER_SIZE)
        recBytes += read(server_socket , buffer+recBytes, BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR while reading the db version");

    //int valread = read(server_socket , buffer, BUFFER_SIZE); 
    EVP_CIPHER_CTX *ctx;
    if(buffer[0]!='4' || buffer[1]!='p') //its parameters message
        abort();
    ctx = EVP_CIPHER_CTX_new ();
    EVP_DecryptInit_ex (ctx , EVP_aes_256_cbc () , NULL , pwd , iv );
    symmetricCrypto symmCrypt_obj;
    unsigned char* s_pt = symmCrypt_obj.sdecrypt (ctx, (unsigned char*)buffer+2, 528+256 );
    element_from_bytes(IBE_obj.P, s_pt);
    element_from_bytes(IBE_obj.K, s_pt+256);
    element_from_bytes(IBE_obj.R, s_pt+256+256);
}

void NewDevice::receive_message4i(int server_socket) {
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);

    size_t recBytes = 0;
    while (recBytes<SMALL_BUFFER_SIZE)
        recBytes += read(server_socket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
    if (recBytes < 0) perror("ERROR reading socket");

    if(buffer[0]!='4' || buffer[1]!='i') //its parameters message
        abort();

    memcpy(&no_of_dev, buffer+2, sizeof(int));
    memcpy(id, buffer+2+sizeof(int), no_of_dev*ID_SIZE);
    memcpy(list_ip, buffer+2+sizeof(int)+(no_of_dev*ID_SIZE), IP_ADDRESS_SIZE*no_of_dev);
    memcpy(list_ports, buffer+2+sizeof(int)+(no_of_dev*ID_SIZE)+(IP_ADDRESS_SIZE*no_of_dev), sizeof(int)*no_of_dev);
    memcpy(list_comm_ports, buffer+2+sizeof(int)+(no_of_dev*ID_SIZE)+(IP_ADDRESS_SIZE*no_of_dev)+sizeof(int)*no_of_dev, sizeof(int)*no_of_dev);
    for(int i=0;i<no_of_dev;i++)
        element_from_hash(Q[i], id[i], ID_SIZE);
}

void NewDevice::send_message5(int server_socket) {
    int j;
    char *buffer = (char *) malloc(sizeof(char) * SMALL_BUFFER_SIZE);
    bzero(buffer, SMALL_BUFFER_SIZE);
    unsigned char* databytes = (unsigned char *)malloc(sizeof(unsigned char) * 256);

    element_random(r);
    element_t aux1, aux2;
    element_init_G1(aux1, IBE_obj.pairing);
    element_init_G1(aux2, IBE_obj.pairing);

    gettimeofday(&op_start,NULL);
    element_mul_zn(aux1, IBE_obj.R, r);
    element_mul_zn(aux2, IBE_obj.P, s);
    element_add(my_COM, aux1, aux2);
    gettimeofday(&op_end,NULL);
    myfile << "Commitment Generation time: " << print_time(&op_start, &op_end) << endl;

    memcpy(buffer, my_id, ID_SIZE);
    element_to_bytes((unsigned char*)buffer+ID_SIZE, my_COM);
    
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc() , NULL , pwd , iv);
    //We need the +1 because it holds the terminating NULL character 
    symmetricCrypto symmCrypt_obj;
    unsigned char* s_ct = symmCrypt_obj.sencrypt(ctx, (unsigned char*)buffer, ID_SIZE+256, &j);

    bzero(buffer, SMALL_BUFFER_SIZE);
    memcpy(buffer, "5", 1);
    memcpy(buffer+1, s_ct, 272);
    send(server_socket, buffer, SMALL_BUFFER_SIZE, 0);
    close(server_socket);
}

void NewDevice::receive_broadcast6() {
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

    if(buffer[0] != '6') {
        cout << "at receive_broadcast6" << endl;
        abort();
    }
    
    unsigned char tempbuff[256];
    signature temp_s(IBE_obj.pairing);
    memcpy(tempbuff, buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int)+256, 256);
    element_from_bytes(temp_s.U, tempbuff);
    memcpy(tempbuff, buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int)+256+256, 256);
    element_from_bytes(temp_s.V, tempbuff);
    if(!IBE_obj.sign_verify((char *)buffer+1, &temp_s, Q[0], ID_SIZE+IP_ADDRESS_SIZE+sizeof(int)+256))
    {
        printf("-------New device commitment request from admin is not verified\n");
        exit(1);
    }

    

    element_from_hash(Q[no_of_dev-1], id+(no_of_dev-1)*ID_SIZE, ID_SIZE);
    element_from_bytes(COM[no_of_dev-1], (unsigned char*)buffer+1+ID_SIZE+IP_ADDRESS_SIZE+sizeof(int));
    memcpy(&id[no_of_dev-1], buffer+1, ID_SIZE);
    //printf("From %s:UDP%u\n", inet_ntoa(remoteAddr.sin_addr), ntohs(remoteAddr.sin_port));
}

void NewDevice::receive_broadcasts7() {
    struct timeval now;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
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
    // if(inet_pton(AF_INET, list_ip[broadcast_no], &sockaddr.sin_addr)<=0) 
    // { 
    //     printf("\nInvalid address/ Address not supported \n"); 
    //     return; 
    // } 

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
    printf("process_broadcast7:Waiting for broadcast7 on port UDP:: %u\n",  BROADCAST_PORT);

    
    int rec_no_coms;
    thread tid[no_of_dev-1];
    for (int rec_no_coms=0; rec_no_coms<no_of_dev-1; rec_no_coms++) {
        int recBytes = 0;
        while (recBytes<SMALL_BUFFER_SIZE)
            //recBytes += read(server_socket , buffer+recBytes, SMALL_BUFFER_SIZE-recBytes);
            recBytes += recvfrom(listeningSocket, buffer+recBytes, SMALL_BUFFER_SIZE-recBytes, 0, (struct sockaddr *)&receiveSockaddr, &receiveSockaddrLen);
        if (recBytes < 0) perror("ERROR while reading the db version");
        tid[rec_no_coms] = thread(&NewDevice::process_broadcast7, this, buffer);
    }
    // int rec_no_coms;
    // thread tid[no_of_dev-1];
    // for (rec_no_coms=0; rec_no_coms<no_of_dev-1; rec_no_coms++) {
        
    // }
    for (rec_no_coms=0; rec_no_coms<no_of_dev-1; rec_no_coms++) {
        tid[rec_no_coms].join();
    }
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
}

void NewDevice::process_broadcast7(char *buffer) {
    printf("process_broadcast7:broadcast7 recieved on port UDP:: %u\n",  BROADCAST_PORT);
    struct timeval now;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;

    if(buffer[0] != '7') {
        cout << "at process_broadcast7" << endl;
        abort();
    }
    unsigned char tempbuff[256];
    signature temp_s(IBE_obj.pairing);
    memcpy(tempbuff, buffer+1+ID_SIZE+256, 256);
    element_from_bytes(temp_s.U, tempbuff);


    memcpy(tempbuff, buffer+1+ID_SIZE+256+256, 256);
    element_from_bytes(temp_s.V, tempbuff);

    int device_id = get_id_index(buffer+1);
    cout << "Taking broadcast 7 from ID : " << device_id << endl;

    gettimeofday(&op_start,NULL);   
    if(!IBE_obj.sign_verify(buffer+1, &temp_s, Q[device_id], ID_SIZE+256))
    {
        printf("-------Commitment msg from admin is not verified\n");
        exit(1);
    }
    gettimeofday(&op_end,NULL);
    myfile << "IBE Signature Verification Time: " << print_time(&op_start, &op_end) << endl;
    
    element_from_bytes(COM[device_id], (unsigned char*)buffer+1+ID_SIZE);

    //element_printf("process_broadcast7:COM[%d]: %B\n", device_id, COM[device_id]);
    cout << "listening for " << list_ip[device_id] << " on" << device_id << endl;
    //close(sd);
}

void NewDevice::exchange_older_messages8(){
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
        cout << "exchange_older_messages8: accepted socket= " << new_socket << endl;
        gettimeofday(&now,NULL);
        cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
        tid[device_no] = thread(&NewDevice::process_message8, this, new_socket);
    }
    for (device_no=0; device_no<my_index; device_no++) {
        tid[device_no].join();
    }

    element_t aux1, aux2;
    element_init_G1(aux1, IBE_obj.pairing);
    element_init_G1(aux2, IBE_obj.pairing);
    element_mul_zn(aux1, IBE_obj.P, s); //aux1 = sP
    element_mul_zn(aux2, my_Q, s); //aux1 = sP
    element_set(sP[my_index], aux1);
    element_set(sQ[my_index], aux2);
}

void NewDevice::process_message8(int new_socket) {
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
    element_init_G1(aux1, IBE_obj.pairing);
    element_init_G1(aux2, IBE_obj.pairing);
    element_init_Zr(t_r, IBE_obj.pairing);
    element_set0(aux1);
    int device_id = 0;
    device_id = get_id_index(buffer+1);
    element_from_bytes(t_r, (unsigned char*)buffer+1+ID_SIZE);
    element_from_bytes(aux1, (unsigned char*)buffer+1+ID_SIZE+256);
    element_from_bytes(aux2, (unsigned char*)buffer+1+ID_SIZE+256+256);
    
    gettimeofday(&op_start,NULL);
    if (!Com_verify(aux1, t_r, COM[device_id])) {
        cout << "-------Commitment Revealed from device " << id[device_id] << " is not verified" << endl;
        exit(1);
    }
    gettimeofday(&op_end,NULL);
    myfile << "Commitment Verififcation time: " << print_time(&op_start, &op_end) << endl;

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

    cout << "process_message8:sending message8 to " << list_ip[device_id] << ":" << list_ports[device_id] << " message8..." << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
    send(new_socket, buffer, BUFFER_SIZE, 0);
    cout << "process_message8:message 8 successfully to " << list_ip[device_id] << ":" << list_ports[device_id] << "" << endl;
    gettimeofday(&now,NULL);
    cout << "now: " << now.tv_sec << ":" << now.tv_usec << endl;
}

int NewDevice::verify_keys() {
    signature temp_s(IBE_obj.pairing);
    char st[] = "Smart Home Security mmmmmmmmmmm just for checking dfhj fjfjdhgjkfhdjghf dfhdjghfdj jfg fdjhgjfdjgkh ddfjh gjkfdjg fdg fhg dfg fdg jkdfhgj fdgdf gkjfdjgkhfd g fdgjdf g dfjkghdfj gjdfg fg jkfdjkg fd f";
    gettimeofday(&op_start,NULL); 
    temp_s = IBE_obj.sign(st, my_Q, temp_D, sizeof(st));
    gettimeofday(&op_end,NULL);
    myfile << "IBE Signature (256 bytes) Time: " << print_time(&op_start, &op_end) << endl;
    if(IBE_obj.sign_verify(st, &temp_s, my_Q, temp_Kpub, sizeof(st)))
        return 1;
    return 0;
}

void NewDevice::send_messageA() {
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

void NewDevice::receive_broadcast9() {
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
    printf("Waiting for broadcast9 on port UDP:: %u\n",  BROADCAST_PORT);

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

int NewDevice::get_id_index(char* t_id) {
    int index = -1;
    for (int i=0; i<no_of_dev; i++)
        if (memcmp(id[i], t_id, 7) == 0)
            index = i;
    return index;
}

void NewDevice::Compute_Network_Public_Key(element_t *t_sp){
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

void NewDevice::Compute_Private_Key(element_t *t_sq){
    element_set0(temp_D);
    for (int i=0; i<no_of_dev; i++)
    {
        element_add(temp_D, temp_D, t_sq[i]);
    }
}

bool NewDevice::Com_verify(element_t t_sp, element_t t_r, element_t t_com){
    element_t aux;
    element_init_G1(aux, IBE_obj.pairing);
    element_mul_zn(aux, IBE_obj.R, t_r);
    element_add(aux, aux, t_sp);
    return (!element_cmp(aux, t_com));
}
double NewDevice::print_time(struct timeval *start, struct timeval *end) {
    double usec;
    usec = (end->tv_sec*1000000 + end->tv_usec) - (start->tv_sec*1000000 +
        start->tv_usec);
    return usec/1000;
}
