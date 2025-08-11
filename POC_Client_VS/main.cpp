#pragma comment (lib, "ws2_32.lib")
#include "WSAInitializer.h"

#include "Client.h"
#include <iostream>
#include <exception>

int main()
{
    try
	{
		WSAInitializer wsaInit;
		Client client;

		client.connectToServer("127.0.0.1", 8876);
		
	}
	catch (std::exception& e)
	{
		std::cout << "Error occured: " << e.what() << std::endl;
	}
	system("PAUSE");
}   