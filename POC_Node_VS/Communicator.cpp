#include "Communicator.h"

std::mutex userSocketMtx;
std::mutex msgMtx;
std::condition_variable cv;
bool ready = false;

std::string msgGlb = "";

Communicator::Communicator(EncryptionManager& encMgr) : encryptionManager(encMgr)
{
	// this communicator use TCP. that why SOCK_STREAM & IPPROTO_TCP
	// if the communicator use UDP we will use: SOCK_DGRAM & IPPROTO_UDP
	_communicatorSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (_communicatorSocket == INVALID_SOCKET)
		throw std::exception(__FUNCTION__ " - socket");
}

Communicator::~Communicator()
{
	try
	{
		// the only use of the destructor should be for freeing 
		// resources that was allocated in the constructor
		closesocket(_communicatorSocket);
	}
	catch (...) {}
}

void Communicator::serve(int port)
{
	struct sockaddr_in sa = { 0 };

	sa.sin_port = htons(port); // port that communicator will listen for
	sa.sin_family = AF_INET;   // must be AF_INET
	sa.sin_addr.s_addr = INADDR_ANY;    // when there are few ip's for the machine. We will use always "INADDR_ANY"

	// Connects between the socket and the configuration (port and etc..)
	if (bind(_communicatorSocket, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR)
		throw std::exception(__FUNCTION__ " - bind");

	// Start listening for incoming requests of clients
	if (listen(_communicatorSocket, SOMAXCONN) == SOCKET_ERROR)
		throw std::exception(__FUNCTION__ " - listen");
	std::cout << "Listening on port " << port << std::endl;

	std::thread acceptorThread(&Communicator::acceptLoop, this);
	acceptorThread.join();
}

void Communicator::acceptClient()
{

	// this accepts the client and create a specific socket from communicator to this client
	// the process will not continue until a client connects to the communicator
	SOCKET client_socket = accept(_communicatorSocket, NULL, NULL);
	if (client_socket == INVALID_SOCKET)
		throw std::exception(__FUNCTION__);

	std::cout << "Client accepted. communicator and client can speak" << std::endl;
	// the function that handle the conversation with the client
	//clientHandler(client_socket);

	std::thread gotClient(&Communicator::clientHandler, this, client_socket);
	gotClient.detach();
}

void Communicator::clientHandler(SOCKET clientSocket)
{
	try
	{
		// ONLY FOR POC -> SO THAT THE CLIENT KNOWS THE PUBLIC KEY
		std::string encRSAPubkey = encryptionManager.getPublicKeyAsString();
		encryptionManager.printPublicKey();
		std::string sendMsg(encRSAPubkey.begin(), encRSAPubkey.end());
		Helper::sendData(clientSocket, sendMsg);

		std::vector<unsigned char> encryptedAESKey = Helper::getPartFromSocketVec(clientSocket, 512, 0);
		encryptionManager.setAESKey(encryptionManager.rsaDecrypt(encryptedAESKey));
	
		std::string result = "Received1";
		std::vector<unsigned char> plaintextVec(result.begin(), result.end());
		std::vector<unsigned char> encryptedMsg = encryptionManager.aesEncrypt(plaintextVec, encryptionManager.getAESKey());

		Helper::sendEncryptedData(clientSocket, encryptedMsg);

		while (true)
		{
			std::vector<unsigned char> decryptedAES = encryptionManager.aesDecrypt(Helper::getPartFromSocketVec(clientSocket, 512, 0), encryptionManager.getAESKey());

			std::string plaintext(reinterpret_cast<const char*>(decryptedAES.data()), decryptedAES.size());

			if (plaintext == "Goodbye")
			{
				std::cout << "\nClient is leaving" << std::endl;
				break;
			}

			std::cout << "\n\nMessage is: " << plaintext << std::endl;

			std::string result = "Received2";
			std::vector<unsigned char> plaintextVec(result.begin(), result.end());
			std::vector<unsigned char> encryptedMsg = encryptionManager.aesEncrypt(plaintextVec, encryptionManager.getAESKey());

			Helper::sendEncryptedData(clientSocket, encryptedMsg);
		}

		std::cout << "Closed socket, Goodbye" << std::endl;
		closesocket(clientSocket);
	}
	catch (const std::exception& e)
	{
		closesocket(clientSocket);
	}
}


void Communicator::acceptLoop()
{
	while (true)
	{
		// the main thread is only accepting clients 
		// and add then to the list of handlers
		std::cout << "Waiting for client connection request" << std::endl;
		acceptClient();
	}
}