#pragma once
#include <QHostAddress>
#include <QDebug>
#include <QTcpSocket>
#include <QJsonDocument>
#include <QJsonObject>

class TlvProtocolHandler final : public QObject {
    Q_OBJECT

public:
    explicit TlvProtocolHandler(QObject *parent = nullptr)
        : QObject(parent), m_socket(new QTcpSocket(this)) {
        connect(m_socket, &QTcpSocket::readyRead, this, [this]() {
            qDebug() << "Triggering readyRead callback...";
            m_buffer.append(m_socket->readAll());
            qDebug() << "Data received from server, buffer size:" << m_buffer.size();
            processBuffer();
        });
    }

    void waitConnect(const QHostAddress &host, const quint16 port,const int msecs = 30000) const {
        qDebug() << "Connecting to host...";
        m_socket->connectToHost(host,port, QTcpSocket::ReadWrite);
        if (!m_socket->waitForConnected(msecs)) {
            qDebug() << "连接超时";
        } else {
            qDebug() << "连接成功";
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
                emit messageReceived(doc.object());
            } else {
                emit errorOccurred("JSON解析失败: " + error.errorString());
            }
        }
    }

    QByteArray m_buffer;
    static constexpr int HeaderSize = 4; // 4字节：表示消息长度
};
