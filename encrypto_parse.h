#pragma once
#include <QHostAddress>
#include <QDebug>
#include <QTcpSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include "encrypto_utils.h"

class EnTlvProtocolHandler final : public QObject {
    Q_OBJECT

public:
    explicit EnTlvProtocolHandler(QObject *parent = nullptr)
        : QObject(parent), m_socket(new QTcpSocket(this)) {
        connect(m_socket, &QTcpSocket::readyRead, this, [this]() {
            qDebug() << "Triggering readyRead callback...";
            m_buffer.append(m_socket->readAll());
            qDebug() << "Data received from server, buffer size:" << m_buffer.size();
            processBuffer();
        });
        auto [publicKey, privateKey] = RSAKeyGenerator::generateRSAKeyPair();
        rsa_private_key_ = privateKey;
        rsa_public_key_ = publicKey;

    }

    void sendRsaPublicKey() const {
        QJsonObject data;
        data["id"] = 10001;
        data["desc"] = "rsa req key";
        data["data"] = QString::fromStdString(base64Encode(rsa_public_key_));
        QByteArray tlvPacket;
        QDataStream stream(&tlvPacket, QIODevice::ReadWrite);
        stream.setByteOrder(QDataStream::BigEndian);

        QByteArray jsonData = QJsonDocument(data).toJson(QJsonDocument::Compact);
        stream << static_cast<quint32>(jsonData.size());
        tlvPacket.append(jsonData);

        auto res = m_socket->write(tlvPacket);
        // m_socket->waitForBytesWritten(100);
        qDebug() << "write tlv " << tlvPacket.size() << " realwrite " << res;
        if (res == -1) {
            qWarning() <<  "Failed to send message!";
        } else {
            qDebug() << "send rsa public key success";
        }
        if (m_socket->state() != QAbstractSocket::ConnectedState) {
            qWarning() << "Socket not connected!";
        }
    }

    void waitConnect(const QHostAddress &host, const quint16 port, const int msecs = 30000) const {
        qDebug() << "Connecting to host...";
        m_socket->connectToHost(host, port, QTcpSocket::ReadWrite);
        if (!m_socket->waitForConnected(msecs)) {
            qDebug() << "连接超时";
        } else {
            qDebug() << "连接成功";
            sendRsaPublicKey();
        }
    }

    void sendMessage(const QJsonObject &data) const {
        QByteArray tlvPacket;
        QDataStream stream(&tlvPacket, QIODevice::ReadWrite);
        stream.setByteOrder(QDataStream::BigEndian);

        QByteArray jsonData = QJsonDocument(data).toJson(QJsonDocument::Compact);
        stream << static_cast<quint32>(jsonData.size());
        tlvPacket.append(jsonData);

        auto res = m_socket->write(tlvPacket);
        // m_socket->waitForBytesWritten(100);
        qDebug() << "write tlv " << tlvPacket.size() << " realwrite " << res;
        if (res == -1) {
            qWarning() << "Failed to send message!";
        } else {
            qDebug() << "Message sent successfully!";
        }
        if (m_socket->state() != QAbstractSocket::ConnectedState) {
            qWarning() << "Socket not connected!";
        }
    }

    QTcpSocket *m_socket;

signals:
    void messageReceived(const QJsonObject &msg);

    void errorOccurred(const QString &error);

private:
    void processBuffer() {
        while (m_buffer.size() >= HeaderSize) {
            // 读取消息头：4字节长度
            const quint32 length = qFromBigEndian<quint32>(m_buffer.constData());
            qDebug() << "Received packet length:" << length;

            if (m_buffer.size() < HeaderSize + length) {
                qDebug() << "Buffer not yet complete, waiting for more data...";
                return; // 数据不完整，等待后续数据
            }

            // 提取JSON数据体
            const QByteArray jsonData = m_buffer.mid(HeaderSize, length);
            m_buffer.remove(0, HeaderSize + length);

            qDebug() << "Received JSON Data: " << jsonData;

            QJsonParseError error;
            QJsonDocument doc = QJsonDocument::fromJson(jsonData, &error);
            if (error.error == QJsonParseError::NoError) {
                auto msg = doc.object();
                if (msg["id"].toInt() == 10002) {
                    auto data = msg["data"].toString().toStdString();

                    // 解码Base64数据
                    auto decoded = base64Decode(data);

                    // 检查解码后的数据长度是否符合预期
                    if (decoded.size() == 32 + 16) {
                        // 提取AES密钥和IV
                        aes_key_ = std::vector<unsigned
                            char>(decoded.begin(), decoded.begin() + 32);
                        aes_iv_ = std::vector<unsigned char>(
                            decoded.begin() + 32, decoded.begin() + 32 +  16);
                        // 打印提取的AES密钥和IV
                        qDebug() << "Extracted AES Key: " << QString::fromStdString(
                            base64Encode(std::string(aes_key_.begin(), aes_key_.end())));
                        qDebug() << "Extracted AES IV: " << QString::fromStdString(
                            base64Encode(std::string(aes_iv_.begin(), aes_iv_.end()))
                        );
                        qDebug() << "AES Key and IV have been successfully extracted.";
                    } else {
                        qWarning() << "Invalid data size, could not extract AES key and IV!";
                    }
                } else {
                    auto data = msg["data"].toString().toStdString();

                    // 解码Base64数据
                    auto decoded = base64Decode(data);
                    // 解密AES数据
                    try {
                        auto decrypted = AesCrypto::aesDecrypt(decoded, aes_key_, aes_iv_);
                        msg["data"] = QString::fromStdString(decrypted);
                        qDebug() << "Received message: " << msg["data"].toString();
                        emit messageReceived(msg);
                    } catch (std::runtime_error &e) {
                        qDebug() << "解密失败: " << e.what();
                    }
                }
            } else {
                emit errorOccurred("JSON解析失败: " + error.errorString());
            }
        }
    }

    QByteArray m_buffer;
    static constexpr int HeaderSize = 4; // 4字节：表示消息长度
    std::string private_key;
    std::vector<unsigned char> aes_key_;
    std::vector<unsigned char> aes_iv_;
    std::string rsa_private_key_;
    std::string rsa_public_key_;
};
