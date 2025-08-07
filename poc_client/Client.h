#pragma once

#include <WinSock2.h>
#include <string>

class Client 
{
public:
    Client();
    ~Client();
    void connectToServer(std::string serverIP, int port);
    void sendData(const std::string& data);
    std::string receiveData();

private:
    SOCKET _clientSocket;
};