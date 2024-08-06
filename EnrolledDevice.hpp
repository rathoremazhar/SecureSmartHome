
/* 
 * File:   EnrolledDevice.hpp
 * Author: muhammad
 *
 * Created on January 20, 2019, 5:30 PM
 */

#ifndef ENROLLEDDEVICE_HPP
#define ENROLLEDDEVICE_HPP

#include <pbc/pbc.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <stdbool.h>
#include <string>

#include "IBE.hpp"

#define MAX_DEV 10 // number of devices allowed
#define IP_ADDRESS_SIZE 20
#define BUFFER_SIZE 2048
#define SMALL_BUFFER_SIZE 1024
#define ID_SIZE 7
#define BROADCAST_PORT 8090
const std::string BROADCAST_ADDRESS = "10.40.222.255";

class EnrolledDevice {
    
public:
    EnrolledDevice();
    EnrolledDevice(const EnrolledDevice& orig);
    virtual ~EnrolledDevice();
    void set_Parameters(IBE* t_IBE_obj, int t_no_of_dev, char* t_my_id, char t_id[][7], char t_list_ip[][IP_ADDRESS_SIZE], int t_list_ports[], int t_local_port, element_t t_my_Q, element_t t_D, element_t t_Q[], unsigned char t_iv[], int t_list_comm_ports[], int t_local_comm_port);
    int start_Device();

private:
	IBE* IBE_obj;
	int no_of_dev;
	char* my_id;
	char id[MAX_DEV][7];
	char list_ip[MAX_DEV][IP_ADDRESS_SIZE]; // for temporary buffer, message, and IDs
	int list_ports[MAX_DEV];
	int list_comm_ports[MAX_DEV];
	int local_port = 0;
	int local_comm_port = 0;
	element_t my_Q;
	element_t D; 
	element_t temp_D; 
	element_t temp_Kpub; //Temporaray storage of Public key
	element_t s; // elements in Z_r
	element_t r; // elements in Z_r 
	element_t my_COM;
	element_t COM[MAX_DEV];
	element_t G[MAX_DEV]; 
	element_t Q[MAX_DEV];
	element_t sQ[MAX_DEV]; //s1.p, s2.p.....
	element_t sP[MAX_DEV]; //s1.Q, s2.Q.....
	unsigned char iv[16];
	unsigned char s_key[MAX_DEV][256];
	EVP_CIPHER_CTX *ctx;
	int get_id_index(char* t_id);
	void update_Gids();
	void Compute_Network_Public_Key(element_t *t_sp);
    void Compute_Private_Key(element_t *t_sq);
    bool Com_verify(element_t t_sp, element_t t_r, element_t t_com); //function to verify the commitment
    void Perform_regular_operations();
    void receive_broadcast6();
    void receive_broadcasts7(int no_broadcasts);
    void process_broadcast7(char *buffer);
    void broadcast_message7();
	void exchange_older_messages8();
    void process_message8(int new_socket);
	void exchange_newer_messages8();
    void send_messageA();
    void receive_broadcast9();
    void Wait_for_message_K();
    void Receive_Session_key_Exchange(int client_socket, char* buffer);
    int verify_keys();

};

#endif 
