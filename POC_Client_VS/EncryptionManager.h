#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <iostream>
#include <vector>
#include <memory>
#include <stdexcept>

class EncryptionManager {
public:
    EncryptionManager(const std::string& nodePubKeyPEM);
    ~EncryptionManager();

    const std::vector<unsigned char>& getEncryptedAESKey();
    const std::vector<unsigned char>& getAESKey();

    std::vector<unsigned char> aesEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key);
    std::vector<unsigned char> aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key);

private:
    RSA* rsaPublicKey;
    std::vector<unsigned char> aesKey;
    std::vector<unsigned char> encryptedAESKey;

    void printErrors();
    void loadRSAPublicKey(const std::string& pubKeyPEM);
    void generateAESKey();
    void encryptAESKey();
};
