#pragma once


#include <QTcpSocket>
#include <type_traits>

#include "encrypto_parse.h"
#include "tlv_parse.h"

enum class MessageType {
    Unknown,

    // 登录相关
    Login = 1000, // 登录类别
    LoginReq, // 登录请求
    LoginRsp, // 登录响应

    // 验证相关
    Verify = 2000, // 验证类别
    VerifyReq, // 验证请求
    VerifyRsp, // 验证响应

    // 退出相关
    Logout = 3000, // 退出类别
    LogoutReq, // 退出请求
    LogoutRsp, // 退出响应

    // 其他不合法的枚举
    End // 结束标志，非法类型
};

static MessageType mapMessageType(const QJsonObject &msg) {
    int msgId = msg["id"].toInt();

    // 1. 如果是非法的Dummy类型或者DummyEnd类型，返回Unknown
    if (msgId == static_cast<int>(MessageType::End) ||
        msgId == static_cast<int>(MessageType::Login) ||
        msgId == static_cast<int>(MessageType::Verify) ||
        msgId == static_cast<int>(MessageType::Logout)) {
        return MessageType::Unknown;
    }

    // 2. 判断所属模块，通过ID范围
    if (msgId >= 1000 && msgId <= 1999) {
        return MessageType::Login; // 属于登录类别
    }

    if (msgId >= 2000 && msgId <= 2999) {
        return MessageType::Verify; // 属于验证类别
    }

    if (msgId >= 3000 && msgId <= 3999) {
        return MessageType::Logout; // 属于退出类别
    }

    // 3. 默认返回Unknown
    return MessageType::Unknown;
}

template<typename Derived>
class MessageHandler {
public:
    static void dispatch(QJsonObject json) {
        Derived::handle(json);
    }

    static constexpr MessageType Type = Derived::Type;
};

template<typename Handler>
concept MessageHandlerConcept = requires
{
    requires std::is_base_of_v<MessageHandler<Handler>, Handler>; // CRTP 继承关系检查
    { Handler::handle(std::declval<QJsonObject>()) } -> std::same_as<void>;
    requires std::is_convertible_v<decltype(Handler::Type), const MessageType>;
};

class TcpManager final : public QObject {
    Q_OBJECT

public:
    explicit TcpManager(QObject *parent = nullptr)
        : QObject(parent), m_handler(new EnTlvProtocolHandler(this)) {
        qDebug() << "TcpManager()";
        connect(m_handler, &EnTlvProtocolHandler::messageReceived,
                this, &TcpManager::slotDispatchMessage);

        connect(m_handler->m_socket, &QTcpSocket::connected, this, [] {
            qDebug() << "Socket connected!";
        });

        connect(m_handler->m_socket, &QTcpSocket::errorOccurred,
                [](const QAbstractSocket::SocketError error) {
                    qWarning() << "Socket error:" << error;
                });

        connect(m_handler->m_socket, &QTcpSocket::disconnected, [] {
            qInfo() << "Socket disconnected.";
        });

        connect(m_handler, &EnTlvProtocolHandler::errorOccurred,
                [](const QString &err) { qWarning() << "Protocol Error:" << err; });
    }

    template<MessageHandlerConcept Handler>
    void registerHandler() {
        if constexpr (Handler::Type == MessageType::Login) {
            // 通过 lambda 自动绑定静态方法
            m_loginHandler = &Handler::dispatch;
        } else {
            static_assert(false, "not handler for MessageType");
        }
    }
    void registerCallback(MessageType type,std::function<void(QJsonObject)> callback) {
        if (type == MessageType::Login) {
            m_loginHandler = callback;
        }
    }
    template<MessageHandlerConcept Handler>
    void unregisterCallback() {
        if constexpr (Handler::Type == MessageType::Login) {
            // 通过 lambda 自动绑定静态方法
            m_loginHandler = {};
        } else {
            static_assert(false, "not handler for MessageType");
        }
    }
Q_SIGNALS:
    void connected();

public Q_SLOTS:
    void slotDispatchMessage(const QJsonObject &msg) const {
        switch (mapMessageType(msg)) {
            case MessageType::Login:
                qDebug() << "dispatch MessageType::Login";
                m_loginHandler(msg); // 登录处理
                break;
            case MessageType::Verify:
                m_verifyHandler(msg); // 验证处理
                break;
            default:
                qWarning() << "Unhandled message type";
        }
    }

    void sendMessage(const QJsonObject &data) const {
        m_handler->sendMessage(data);
    }

public:
    EnTlvProtocolHandler *m_handler{};

private:
    std::function<void(QJsonObject)> m_loginHandler;
    std::function<void(QJsonObject)> m_verifyHandler;

    template<typename>
    static constexpr bool always_false = false;
};
