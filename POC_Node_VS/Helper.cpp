#include "Helper.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

using std::string;

// recieves the type code of the message from socket (3 bytes)
// and returns the code. if no message found in the socket returns 0 (which means the client disconnected)
int Helper::getMessageTypeCode(const SOCKET sc)
{
	std::string msg = getPartFromSocket(sc, 3, 0);

	if (msg == "")
		return 0;

	int res = std::atoi(msg.c_str());
	return  res;
}


// recieve data from socket according byteSize
// returns the data as int
int Helper::getIntPartFromSocket(const SOCKET sc, const int bytesNum)
{
	return atoi(getPartFromSocket(sc, bytesNum, 0).c_str());
}

// recieve data from socket according byteSize
// returns the data as string
string Helper::getStringPartFromSocket(const SOCKET sc, const int bytesNum)
{
	return getPartFromSocket(sc, bytesNum, 0);
}

// return string after padding zeros if necessary
string Helper::getPaddedNumber(const int num, const int digits)
{
	std::ostringstream ostr;
	ostr << std::setw(digits) << std::setfill('0') << num;
	return ostr.str();
}

// recieve data from socket according byteSize
// this is private function
std::string Helper::getPartFromSocket(const SOCKET sc, const int bytesNum)
{
	return getPartFromSocket(sc, bytesNum, 0);
}

// send data to socket
// this is private function
void Helper::sendData(const SOCKET sc, const std::string message)
{
	const char* data = message.c_str();

	if (send(sc, data, message.size(), 0) == INVALID_SOCKET)
	{
		throw std::exception("Error while sending message to client");
	}
}

std::vector<unsigned char> Helper::getPartFromSocketVec(const SOCKET sc, const int bytesNum, const int flags)
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



std::string Helper::getPartFromSocket(const SOCKET sc, const int bytesNum, const int flags)
{
	if (bytesNum == 0)
	{
		return "";
	}

	char* data = new char[bytesNum + 1];
	int res = recv(sc, data, bytesNum, flags);
	if (res == 0)
	{
		// Client disconnects
		delete[] data;
		return "";
	}
	else if (res == INVALID_SOCKET)
	{
		std::string s = "Error while recieving from socket: ";
		s += std::to_string(sc);
		throw std::exception(s.c_str());
	}
	data[bytesNum] = 0;
	std::string received(data);
	delete[] data;

	received.erase(std::find_if(received.rbegin(), received.rend(), [](unsigned char ch) {
		return std::isprint(ch);
		}).base(), received.end());

	return received;
}

uint32_t Helper::readMessageLength(SOCKET sc)
{
	uint32_t len = 0;
	auto lenBytes = Helper::receiveExact(sc, sizeof(len));
	if (lenBytes.size() != sizeof(len)) {
		throw std::runtime_error("Failed to read message length");
	}
	// Convert from network byte order to host byte order
	memcpy(&len, lenBytes.data(), sizeof(len));
	len = ntohl(len);
	return len;
}


std::vector<unsigned char> Helper::receiveExact(SOCKET sc, size_t bytesNum) 
{
	std::vector<unsigned char> buffer(bytesNum);
	size_t totalReceived = 0;

	while (totalReceived < bytesNum) {
		int res = recv(sc, reinterpret_cast<char*>(buffer.data() + totalReceived), bytesNum - totalReceived, 0);
		if (res <= 0) {
			// error or disconnect
			buffer.clear();
			break;
		}
		totalReceived += res;
	}

	if (totalReceived < bytesNum) {
		// incomplete read, handle error
		buffer.clear();
	}

	return buffer;
}

void Helper::sendEncryptedData(const SOCKET sc, const std::vector<unsigned char>& encryptedData)
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
