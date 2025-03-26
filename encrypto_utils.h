#pragma once


#include <iomanip>
#include <vector>
#include <string>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/types.h>

std::vector<unsigned char> base64Decode(const std::string &encoded_data);

std::string base64Encode(const auto &data) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    BUF_MEM *buffer;
    BIO_get_mem_ptr(bio, &buffer);
    std::string result(buffer->data, buffer->length);
    BIO_free_all(bio);
    return result;
}

class AesCrypto {
public:
    static void generateRandomKeyIV(std::vector<unsigned char> &key,
                                    std::vector<unsigned char> &iv);

    static std::vector<unsigned char> aesEncrypt(const std::string &plaintext,
                                                 const std::vector<unsigned char> &key,
                                                 const std::vector<unsigned char> &iv);

    static std::string aesDecrypt(const std::vector<unsigned char> &ciphertext,
                                  const std::vector<unsigned char> &key,
                                  const std::vector<unsigned char> &iv);
};

class RSAEncryptor {
public:
    struct Result {
        std::vector<unsigned char> data;
        int length;

        std::string toString() const;

        std::string toHex() const;
    };

    static Result publicEncrypt(const std::string &plainText, const std::string &publicKey);

    static Result privateDecrypt(const std::vector<unsigned char> &cipherText,
                                 const std::string &privateKey);

private:
    static std::string getOpenSSLError();
};

class RSAKeyGenerator {
public:
    static std::pair<std::string, std::string> generateRSAKeyPair(int keySize = 2048);
};
