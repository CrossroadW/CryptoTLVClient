#pragma once


#include <iomanip>
#include <vector>
#include <string>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/types.h>
inline std::vector<unsigned char> base64Decode(const std::string &encoded_data) {
    // 创建一个BIO对象，用于Base64解码
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(encoded_data.data(), encoded_data.size());
    bio = BIO_push(b64, bio);

    // 禁用Base64解码时的换行符处理
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    // 读取解码后的数据
    std::vector<unsigned char> decoded_data(encoded_data.size());  // 分配足够大的空间
    int decoded_size = BIO_read(bio, decoded_data.data(), encoded_data.size());

    // 可能解码后的数据量比原始Base64字符串小，调整大小
    decoded_data.resize(decoded_size);

    BIO_free_all(bio);

    return decoded_data;
}
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
