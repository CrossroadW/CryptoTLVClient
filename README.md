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

## 编译与运行

### 克隆项目

```bash
git clone https://github.com/yourusername/CryptoTLVClient.git
cd CryptoTLVClient
