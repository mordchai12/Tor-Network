#include "EncryptionManager.h"

EncryptionManager::EncryptionManager(const std::string& nodePubKeyPEM) : rsaPublicKey(nullptr)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    loadRSAPublicKey(nodePubKeyPEM);
    generateAESKey();
    encryptAESKey();
}

EncryptionManager::~EncryptionManager() 
{
    if (rsaPublicKey) RSA_free(rsaPublicKey);
    EVP_cleanup();
    ERR_free_strings();
}

// Returns encrypted AES key bytes (send these to node)
const std::vector<unsigned char>& EncryptionManager::getEncryptedAESKey() 
{
    return encryptedAESKey;
}

// Returns raw AES key bytes (use locally for AES encrypt/decrypt)
const std::vector<unsigned char>& EncryptionManager::getAESKey() 
{
    return aesKey;
}


void EncryptionManager::printErrors() 
{
    unsigned long err;
    while ((err = ERR_get_error())) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << "OpenSSL error: " << buf << std::endl;
    }
}

void EncryptionManager::loadRSAPublicKey(const std::string& pubKeyPEM) 
{
    BIO* bio = BIO_new_mem_buf(pubKeyPEM.data(), static_cast<int>(pubKeyPEM.size()));
    if (!bio) throw std::runtime_error("Failed to create BIO");

    rsaPublicKey = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!rsaPublicKey) {
        printErrors();
        throw std::runtime_error("Failed to load RSA public key");
    }
}

void EncryptionManager::generateAESKey() 
{
    aesKey.resize(32); // 256 bits
    if (RAND_bytes(aesKey.data(), static_cast<int>(aesKey.size())) != 1) {
        printErrors();
        throw std::runtime_error("Failed to generate AES key");
    }
}

void EncryptionManager::encryptAESKey() 
{
    encryptedAESKey.resize(RSA_size(rsaPublicKey));
    int len = RSA_public_encrypt(
        static_cast<int>(aesKey.size()),
        aesKey.data(),
        encryptedAESKey.data(),
        rsaPublicKey,
        RSA_PKCS1_OAEP_PADDING
    );

    if (len == -1) {
        printErrors();
        throw std::runtime_error("RSA encryption failed");
    }

    encryptedAESKey.resize(len);
}

std::vector<unsigned char> EncryptionManager::aesEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key)
{
    if (key.size() != 32) throw std::runtime_error("Key must be 32 bytes for AES-256");

    std::vector<unsigned char> iv(16);
    if (!RAND_bytes(iv.data(), iv.size()))
        throw std::runtime_error("Failed to generate IV");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()))
        throw std::runtime_error("EVP_EncryptInit_ex failed");

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    int ciphertext_len = 0;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), (int)plaintext.size()))
        throw std::runtime_error("EVP_EncryptUpdate failed");
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);

    // Prepend IV to ciphertext (so receiver can extract it)
    ciphertext.insert(ciphertext.begin(), iv.begin(), iv.end());

    return ciphertext;
}

// Decrypt ciphertext using AES-256-CBC.
// Input:
// - ciphertext: IV (16 bytes) + encrypted data
// - key: 32 bytes AES key
// Output:
// - decrypted plaintext
std::vector<unsigned char> EncryptionManager::aesDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key)
{
    if (key.size() != 32) throw std::runtime_error("Key must be 32 bytes for AES-256");
    if (ciphertext.size() < 16) throw std::runtime_error("Ciphertext too short");

    const unsigned char* iv = ciphertext.data();
    const unsigned char* enc_data = ciphertext.data() + 16;
    int enc_data_len = (int)ciphertext.size() - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_CIPHER_CTX");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv))
        throw std::runtime_error("EVP_DecryptInit_ex failed");

    std::vector<unsigned char> plaintext(enc_data_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    int plaintext_len = 0;

    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, enc_data, enc_data_len))
        throw std::runtime_error("EVP_DecryptUpdate failed");
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    plaintext.resize(plaintext_len);
    return plaintext;
}