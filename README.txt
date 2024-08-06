###########Compiling the whole project/Implmentation (all classes)###########################################

g++ -std=c++11 main.cpp Admin.cpp NewDevice.cpp IBE.cpp ciphertext.cpp signature.cpp symmetricCrypto.cpp EnrolledDevice.cpp -lcrypto -lgmp -lpbc -pthread -o smatHome



###############Copying the file from PC to boards##### From one computer to another using SCP###########

scp -r ../smartHome pi@10.40.222.133:/home/pi/Desktop/; scp -r ../smartHome pi@10.40.222.135:/home/pi/Desktop/


scp -r  sourcefolder  Destination



#########################################################################################################

##############Help For Runing the program.... To see the command possible option #################

./smatHome -h


./name-of-the-exefile -h   (Formate)

##########################################################################################################

################Running the program... The Admin Device/Server#############

./smatHome -a


./name-of-the-exefile -a   (Formate -a for admin device)


#########################################################################################################

################Running the program... The Cleint Device/Home device-on Raspberry Pi (after running the admin)###########

./smatHome -d --id device2 --serverIP 10.40.222.143 --clientPort 8082


(Formate)
./name-of-the-exefile -d --id device2 --serverIP 10.40.222.143 --clientPort 8082  (Command Formate, -d for homedevice, --id you are giving the id at run time, "device2" is the id/name of the device with 7 characters Thus id := device2, --serverIP shows that you are giving the server/Admin IP-bydefault it is localserver, 10.40.222.143 is the admin IP, and then you give the client port that would be used by the home device for receiving the messages: it can be any port.

####################################################################################################################   
