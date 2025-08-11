#pragma comment (lib, "ws2_32.lib")
#include <iostream>
#include "WSAInitializer.h"
#include "Communicator.h"
#include "EncryptionManager.h"

void main()
{
	try
	{
		WSAInitializer wsaInit;
		EncryptionManager encManager;
		Communicator myCommunicator(encManager);


		myCommunicator.serve(8876);
	}
	catch (std::exception& e)
	{
		std::cout << "Error occured: " << e.what() << std::endl;
	}
	system("PAUSE");
}