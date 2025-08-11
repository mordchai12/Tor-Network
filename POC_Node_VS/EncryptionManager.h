#pragma once
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>

class EncryptionManager 
{
public:
    EncryptionManager();
    ~EncryptionManager();

    void printPublicKey();
    std::string getPublicKeyAsString();

    void setAESKey(std::vector<unsigned char> key);
    std::vector<unsigned char> getAESKey() const;
    std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key);
    std::vector<unsigned char> aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key);

    std::vector<unsigned char> rsaDecrypt(const std::vector<unsigned char>& encryptedData) const;
private:
    RSA* rsaKey = nullptr;
    void printErrors();
    RSA* generateRSAKey();
    std::vector<unsigned char> AESKey;
};