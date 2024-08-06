/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   main.cpp
 * Author: muhammad
 *
 * Created on January 20, 2019, 5:28 PM
 */

#include <cstdlib>
#include <pbc/pbc.h>
#include <iostream>
#include <string>
#include <cstring>

#include "Admin.hpp"
#include "NewDevice.hpp"
#include "cxxopts.hpp"

using namespace std;

/*
 * 
 */
int main(int argc, char** argv) {
	string serverIP = "10.40.222.143";
	string id = "SmartTV";
	int serverPort = 8080;
	int clientPort = 8080;
	int commPort = 8089;
	try {
		cxxopts::Options options("MyProgram", "One line description of MyProgram");
		options.add_options()
			("a,admin", "Start as Admin")
			("d,device", "Start as Device")
			("id", "Device ID", cxxopts::value<string>())
			("serverIP", "Server IP", cxxopts::value<string>())
			("serverPort", "Server port", cxxopts::value<int>())
			("clientPort", "Client port", cxxopts::value<int>())
			("commPort", "Communication port", cxxopts::value<int>())
			("h,help", "Print help");
		auto result = options.parse(argc, argv);
		if (result.count("help")) {
			cout << options.help();
			exit(1);
		}
		if (result.count("serverIP"))
			serverIP = result["serverIP"].as<string>();
		if (result.count("serverPort"))
			serverPort = result["serverPort"].as<int>();
		if (result.count("clientPort"))
			clientPort = result["clientPort"].as<int>();
		if (result.count("commPort"))
			commPort = result["commPort"].as<int>();
		if (result.count("id"))
			id = result["id"].as<string>();
		if (result.count("admin")) {
			Admin Admin_obj;
    		Admin_obj.start_Server(serverIP, serverPort, commPort);
		}
		if (result.count("device")) {
    		NewDevice Device_obj(id);
    		Device_obj.start_Device(serverIP, serverPort, clientPort, commPort);
		}

	} catch (const cxxopts::OptionException& e) {
		cout << "error parsing options:" << e.what() << endl;
		exit(1);
	}

    return 0;
}

