#pragma once

#include <WinSock2.h>
#include <Windows.h>
#include <queue>
#include <map>
#include <iostream>
#include <string>
#include <cstring>
#include <mutex>
#include <exception>
#include <iostream>
#include <string>
#include <thread>
#include <condition_variable>
#include <fstream>
#include <ctime>
#include "Helper.h";
#include "EncryptionManager.h"

class Communicator
{
public:
	Communicator(EncryptionManager& encMgr);
	~Communicator();
	void serve(int port);
private:
	void acceptClient();
	void clientHandler(SOCKET clientSocket);
	void acceptLoop();

	SOCKET _communicatorSocket;
	static std::vector<SOCKET> m_clients;
	EncryptionManager& encryptionManager;
};

#pragma once
