
/* 
 * File:   Device.hpp
 * Author: muhammad
 *
 * Created on January 20, 2019, 5:30 PM
 */

#ifndef Device_HPP
#define Device_HPP

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
//const std::string BROADCAST_ADDRESS = "255.255.255.255";

class Device {
    
public:
    Device(std::string n_id);
    Device(const Device& orig);
    virtual ~Device();
    int start_Device(std::string server_ip, int server_port, int t_local_port);

private:
	IBE IBE_obj;
	signature* stamp_ptr;
	int no_of_dev;
	char my_id[7];
	char id[MAX_DEV][7];
	char list_ip[MAX_DEV][IP_ADDRESS_SIZE]; // for temporary buffer, message, and IDs
	int list_ports[MAX_DEV];
	int local_port = 8080;
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
	unsigned char iv[16]; //vectore for symetric encryption
	unsigned char pwd [32];
	int get_id_index(char* t_id);
	void update_Gids();
	void Compute_Network_Public_Key(element_t *t_sp);
    void Compute_Private_Key(element_t *t_sq);
    bool Com_verify(element_t t_sp, element_t t_r, element_t t_com); //function to verify the commitment
    void send_message1(int server_socket);
	void receive_message2(int server_socket);
    void send_message3(int server_socket);
	void receive_message4p(int server_socket);
	void receive_message4s(int server_socket);
	void receive_message4i(int server_socket);
    void send_message5(int server_socket);
    void receive_broadcast6();
    void receive_broadcasts7();
    void process_broadcast7();
	void exchange_older_messages8();
    void process_message8();
   

};

#endif 
