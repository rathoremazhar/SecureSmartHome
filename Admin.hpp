
/* 
 * File:   Admin.hpp
 * Author: muhammad
 *
 * Created on January 20, 2019, 5:30 PM
 */

#ifndef Admin_HPP
#define Admin_HPP

#include <pbc/pbc.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <stdbool.h>
#include <string>
#include <sys/time.h>
#include <fstream>

#include "IBE.hpp"


#define MAX_DEV 10 // number of devices allowed
#define IP_ADDRESS_SIZE 20
#define BUFFER_SIZE 2048
#define SMALL_BUFFER_SIZE 1024
#define ID_SIZE 7
#define BROADCAST_PORT 8090
const std::string BROADCAST_ADDRESS = "10.40.222.255";

using namespace std;

class Admin {
    
public:
    Admin();
    Admin(const Admin& orig);
    virtual ~Admin();
	void start_Server(std::string server_ip, int server_port, int t_commPort);

private:
	IBE IBE_obj;
	int no_of_dev;
	char my_id[ID_SIZE];
	char id[MAX_DEV][ID_SIZE];
	char list_ip[MAX_DEV][IP_ADDRESS_SIZE]; // for temporary buffer, message, and IDs
	int list_ports[MAX_DEV];
	int list_comm_ports[MAX_DEV];
	element_t my_Q;
	element_t D; 
	element_t temp_D; // for temporary storing new key
	element_t temp_Kpub; //Temporaray storage of Public key
	element_t s; // elements in Z_r
	element_t r; // elements in Z_r
	element_t my_COM;
	element_t COM[MAX_DEV]; 
	element_t G[MAX_DEV]; 
	element_t Q[MAX_DEV]; 
	element_t sQ[MAX_DEV]; //s1.p, s2.p.....
	element_t sP[MAX_DEV]; //s1.Q, s2.Q.....
	unsigned char iv[16]; //vectore for symetric encryption
	unsigned char pwd[32];
	unsigned char s_key[MAX_DEV][256];
	EVP_CIPHER_CTX *ctx;
	int noVerifiedKeys = 0;
	bool allKeysVerified = false;
	int get_id_index(char* t_id);
	void update_Gids();
	int seed_prng();
	void Compute_Network_Public_Key(element_t *t_sp);
    void Compute_Private_Key(element_t *t_sq);
    bool Com_verify(element_t t_sp,element_t t_r,element_t t_com); //function to verify the commitment
	void serve_New_Client(int client_socket, char *buffer);
	void receive_message1(int client_socket, char *buffer);
	void send_message2(int client_socket);
	void receive_message3(int client_socket);
	void send_message4p(int client_socket);
	void send_message4i(int client_socket);
	void receive_message5(int client_socket);
	void broadcast_message6();
	void broadcast_message7();
    void receive_broadcasts7();
    void process_broadcast7();
	void exchange_newer_messages8();
	void process_messageA(char *buffer);
	void broadcast_message9();
	void Send_Session_key_Exchange();
	void Receive_Session_key_Exchange(int client_socket, char* buffer);
    bool verify_keys();
	double print_time(struct timeval *start, struct timeval *end);

	ofstream myfile;
	struct timeval basic_op_start, basic_op_end;
	struct timeval op_start, op_end;
	struct timeval phase_start, phase_end;
	struct timeval proto_start, proto_end;

};

#endif /* Admin_HPP */
