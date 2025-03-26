# CryptoTLVClient

`CryptoTLVClient` 是一个基于 TLV 协议和 OpenSSL 加密的客户端应用，使用 CRTP（Curiously Recurring Template Pattern）设计模式，提供无虚函数的高效实现。

## 特性

- **TLV 协议支持**：支持 TLV（Type-Length-Value）协议的数据处理与解析。
- **OpenSSL 加密**：利用 OpenSSL 实现数据加密和解密。
- **无虚函数设计**：使用 CRTP 模式避免虚函数，提高性能和可扩展性。
- **安全通信**：实现了安全的客户端-服务器通信协议，确保数据传输的保密性和完整性。
- **模块化设计**：清晰的模块划分，易于扩展与维护。

## 依赖

- C++17 或更高版本
- Qt 5.15 或更高版本
- OpenSSL 1.1 或更高版本

## 架构

- `TcpManager`：管理 TCP 连接和协议解析。
- `MessageHandler`：消息处理的基类，使用 CRTP 模式处理不同类型的消息。
- `LoginHandler`：登录相关的消息处理程序。
- `EnTlvProtocolHandler`：处理 TLV 协议的编解码。
## 例子
```c++
class LoginHandler : public MessageHandler<LoginHandler> {
    public:
        static constexpr auto Type = MessageType::Login; // 登录模块的起始类型

        static void handle(QJsonObject json) {
            // 通过 MessageType 来判断处理不同的消息
            switch (int msgId = json["id"].toInt(); static_cast<MessageType>(msgId)) {
                case MessageType::LoginRsp:
                    qDebug() << "处理登录响应 (LoginRsp):" << json;
                    break;
                default:
                    qWarning() << "没有匹配的处理程序，ID:" << msgId;
                    break;
            }
        }
    };
    
...

m_tcpManager = new TcpManager(this);
m_tcpManager->registerHandler<LoginHandler>();
```
### 克隆项目

```bash
git clone https://github.com/CrossroadW/CryptoTLVClient
cd CryptoTLVClient
