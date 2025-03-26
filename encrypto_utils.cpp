#include "encrypto_utils.h"
#include <cassert>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>

#include <stdexcept>
#include <openssl/err.h>
#include <openssl/pem.h>



void AesCrypto::generateRandomKeyIV(std::vector<unsigned char> &key,
    std::vector<unsigned char> &iv) {
    if (RAND_bytes(key.data(), key.size()) != 1 || RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Failed to generate random key or IV");
    }
}

std::vector<unsigned char> AesCrypto::aesEncrypt(const std::string &plaintext,
    const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::string AesCrypto::aesDecrypt(const std::vector<unsigned char> &ciphertext,
    const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }
    int plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.end());
}

std::string RSAEncryptor::Result::toString() const {
    return std::string(reinterpret_cast<const char *>(data.data()), length);
}

std::string RSAEncryptor::Result::toHex() const {
    std::ostringstream oss;
    for (int i = 0; i < length; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int) data[i] << " ";
    }
    return oss.str();
}

RSAEncryptor::Result RSAEncryptor::publicEncrypt(const std::string &plainText,
    const std::string &publicKey) {
    BIO *bio = BIO_new_mem_buf(publicKey.data(), publicKey.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for public key");
    }

    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) {
        throw std::runtime_error("Failed to load public key");
    }

    int rsaSize = RSA_size(rsa);
    std::vector<unsigned char> encrypted(rsaSize);

    int result = RSA_public_encrypt(
        plainText.size(),
        reinterpret_cast<const unsigned char *>(plainText.data()),
        encrypted.data(),
        rsa,
        RSA_PKCS1_PADDING
    );

    RSA_free(rsa);

    if (result == -1) {
        throw std::runtime_error("Public key encryption failed: " + getOpenSSLError());
    }

    return {encrypted, result};
}

RSAEncryptor::Result RSAEncryptor::privateDecrypt(const std::vector<unsigned char> &cipherText,
    const std::string &privateKey) {
    BIO *bio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!rsa) {
        throw std::runtime_error("Failed to load private key");
    }

    int rsaSize = RSA_size(rsa);
    std::vector<unsigned char> decrypted(rsaSize);

    int result = RSA_private_decrypt(
        cipherText.size(),
        cipherText.data(),
        decrypted.data(),
        rsa,
        RSA_PKCS1_PADDING
    );

    RSA_free(rsa);

    if (result == -1) {
        throw std::runtime_error("Private key decryption failed: " + getOpenSSLError());
    }

    return {decrypted, result};
}

std::string RSAEncryptor::getOpenSSLError() {
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = nullptr;
    long size = BIO_get_mem_data(bio, &buf);
    std::string error(buf, size);
    BIO_free(bio);
    return error;
}

std::pair<std::string, std::string> RSAKeyGenerator::generateRSAKeyPair(int keySize) {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);

    // 生成密钥对
    if (!RSA_generate_key_ex(rsa, keySize, bn, nullptr)) {
        BN_free(bn);
        RSA_free(rsa);
        throw std::runtime_error("Failed to generate RSA key pair");
    }

    // 生成私钥字符串
    BIO *privateBio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(privateBio, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    char *privateKeyBuffer;
    long privateKeyLen = BIO_get_mem_data(privateBio, &privateKeyBuffer);
    std::string privateKey(privateKeyBuffer, privateKeyLen);
    BIO_free(privateBio);

    // 生成公钥字符串
    BIO *publicBio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(publicBio, rsa);
    char *publicKeyBuffer;
    long publicKeyLen = BIO_get_mem_data(publicBio, &publicKeyBuffer);
    std::string publicKey(publicKeyBuffer, publicKeyLen);
    BIO_free(publicBio);

    BN_free(bn);
    RSA_free(rsa);

    return {publicKey, privateKey};
}
