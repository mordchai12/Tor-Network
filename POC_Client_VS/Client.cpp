#include "Client.h"
#include <iostream>
#include <exception>
#include <stdexcept>
#include <WS2tcpip.h>
#include "EncryptionManager.h"

Client::Client()
{
	// we connect to server that uses TCP. thats why SOCK_STREAM & IPPROTO_TCP
	_clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (_clientSocket == INVALID_SOCKET)
		throw std::runtime_error(std::string(__FUNCTION__) + " - socket");
}

Client::~Client()
{
	try
	{
		// the only use of the destructor should be for freeing 
		// resources that was allocated in the constructor
		closesocket(_clientSocket);
	}
	catch (...) {}
}


void Client::connectToServer(std::string serverIP, int port)
{
	struct sockaddr_in sa = { 0 };

	sa.sin_port = htons(port); // port that server will listen to
	sa.sin_family = AF_INET;   // must be AF_INET

	if (inet_pton(AF_INET, serverIP.c_str(), &sa.sin_addr) <= 0) {
		throw std::runtime_error("Invalid IP address format");
	}

	// the process will not continue until the server accepts the client
	int status = connect(_clientSocket, (struct sockaddr*)&sa, sizeof(sa));

	if (status == INVALID_SOCKET)
		throw std::runtime_error("Cant connect to server");

	manageConnection();
}

void Client::sendData(const std::string& data) 
{
    send(_clientSocket, data.c_str(), data.size(), 0);
}

std::string Client::receiveData() 
{
    char buffer[1024];
    int bytesReceived = recv(_clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        return std::string(buffer, bytesReceived);
    }
    return "";
}
std::vector<unsigned char> Client ::getPartFromSocketVec(const SOCKET sc, const int bytesNum, const int flags)
{
	if (bytesNum == 0)
	{
		return {};
	}

	std::vector<unsigned char> buffer(bytesNum);
	int res = recv(sc, reinterpret_cast<char*>(buffer.data()), bytesNum, flags);

	if (res == 0)
	{
		// Client disconnected
		return {};
	}
	else if (res == INVALID_SOCKET)
	{
		std::string s = "Error while receiving from socket: " + std::to_string(sc);
		throw std::exception(s.c_str());
	}

	// Resize to actual bytes received
	buffer.resize(res);

	return buffer;
}


void Client::sendEncryptedData(const SOCKET sc, const std::vector<unsigned char>& encryptedData)
{
	int dataSize = static_cast<int>(encryptedData.size());

	if (dataSize == 0) {
		return; // nothing to send
	}

	int sent = send(sc,
		reinterpret_cast<const char*>(encryptedData.data()),
		dataSize,
		0);

	if (sent == SOCKET_ERROR || sent != dataSize) {
		throw std::runtime_error("Failed to send all encrypted data in one call");
	}
}

void Client::manageConnection()
{
	std::string publicRSAKey = "";

	publicRSAKey = receiveData();

	std::cout << "Received the Data: " << publicRSAKey << std::endl;

	if (!publicRSAKey.empty())
	{
		EncryptionManager encManager(publicRSAKey);

		// Use encManager to get encrypted AES key, send it, etc.
		auto encryptedKey = encManager.getEncryptedAESKey();

		// send encryptedKey over the socket
		sendData(std::string(encryptedKey.begin(), encryptedKey.end()));

		std::vector<unsigned char> decryptedAES = encManager.aesDecrypt(getPartFromSocketVec(_clientSocket, 512, 0), encManager.getAESKey());
		std::string decryptedStr1(decryptedAES.begin(), decryptedAES.end());
		std::cout << "Msg recv: " << decryptedStr1 << std::endl; 

		std::string result = "Hiiiii!";
		std::vector<unsigned char> plaintextVec1(result.begin(), result.end());
		sendEncryptedData(_clientSocket, encManager.aesEncrypt(plaintextVec1, encManager.getAESKey()));

		std::cout << "Sent: " << result << std::endl;
		
		decryptedAES = encManager.aesDecrypt(getPartFromSocketVec(_clientSocket, 512, 0), encManager.getAESKey());
		std::string decryptedStr2(decryptedAES.begin(), decryptedAES.end());
		std::cout << "Msg recv: " << decryptedStr2 << std::endl;
			
		result = "Goodbye";
		std::vector<unsigned char> plaintextVec2(result.begin(), result.end());
		sendEncryptedData(_clientSocket, encManager.aesEncrypt(plaintextVec2, encManager.getAESKey()));

		std::cout << "Sent: " << result << std::endl;
	}
}
