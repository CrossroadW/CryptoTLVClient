import socket
import json
import struct
from datetime import datetime
import threading

# 枚举类，用于表示消息类型
class MessageType:
    Unknown = 0
    DummyLogin = 1000
    LoginReq = 1001
    LoginRsp = 1002
    DummyVerify = 2000
    VerifyReq = 2001
    VerifyRsp = 2002
    DummyLogout = 3000
    LogoutReq = 3001
    LogoutRsp = 3002
    DummyEnd = 9999  # 非法类型

# 根据消息的 id 返回对应的 MessageType
def map_message_type(msg_id):
    if 1000 <= msg_id < 2000:
        return MessageType.DummyLogin
    elif 2000 <= msg_id < 3000:
        return MessageType.DummyVerify
    elif 3000 <= msg_id < 4000:
        return MessageType.DummyLogout
    else:
        return MessageType.Unknown

class SimpleServer:
    def __init__(self, host='127.0.0.1', port=5555):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(10)  # 允许最多10个客户端连接
        print(f"服务器启动在 {host}:{port}")

    def handle_client(self, conn, addr):
        """处理每个客户端连接"""
        print(f"新连接: {addr}")
        try:
            while True:
                # 读取TLV协议数据
                data = self.receive_tlv_data(conn)
                if data:
                    print(f"接收到数据来自 {addr}: {data}")

                    # 根据id判断消息类型
                    msg_id = data.get("id")
                    message_type = map_message_type(msg_id)

                    if message_type == MessageType.DummyLogin:
                        self.send_login_response(conn, data)
                    elif message_type == MessageType.DummyVerify:
                        self.send_verify_response(conn, data)
                    elif message_type == MessageType.DummyLogout:
                        self.send_logout_response(conn, data)
                    else:
                        print(f"未知的消息类型 {message_type} 来自 {addr}")
                else:
                    print(f"连接 {addr} 断开")
                    break
        finally:
            conn.close()
            print(f"连接关闭: {addr}")

    def receive_tlv_data(self, conn):
        """读取TLV格式的数据: 先接收长度，再接收数据"""
        try:
            # 读取4字节长度头（大端字节序）
            header = conn.recv(4)
            if len(header) < 4:
                return None  # 没有接收到完整的长度头

            # 转换为整数（大端字节序）
            length = struct.unpack('>I', header)[0]
            print(f"接收到的消息长度: {length}")

            # 根据长度读取数据
            data = b''
            while len(data) < length:
                packet = conn.recv(length - len(data))
                if not packet:
                    return None  # 如果没有数据了，断开连接
                data += packet

            # 将接收到的字节数据解码为字符串并解析为JSON
            print(f"接收到的原始数据: {data}")
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"接收或解析数据错误: {str(e)}")
            return None

    def send_login_response(self, conn, request_data):
        """发送登录响应"""
        response = {
            "id": MessageType.LoginRsp,
            "status": "success",
            "message": "Login successful",
            "timestamp": int(datetime.now().timestamp())
        }
        print(f"发送登录响应: {response}")

        # TLV 编码响应消息
        tlv_packet = self.encode_tlv(response)

        # 发送响应
        conn.send(tlv_packet)

        print("登录响应已发送.")

    def send_verify_response(self, conn, request_data):
        """发送验证响应"""
        response = {
            "id": MessageType.VerifyRsp,
            "status": "success",
            "message": "Verification successful",
            "timestamp": int(datetime.now().timestamp())
        }
        print(f"发送验证响应: {response}")

        # TLV 编码响应消息
        tlv_packet = self.encode_tlv(response)

        # 发送响应
        conn.send(tlv_packet)

        print("验证响应已发送.")

    def send_logout_response(self, conn, request_data):
        """发送退出响应"""
        response = {
            "id": MessageType.LogoutRsp,
            "status": "success",
            "message": "Logout successful",
            "timestamp": int(datetime.now().timestamp())
        }
        print(f"发送退出响应: {response}")

        # TLV 编码响应消息
        tlv_packet = self.encode_tlv(response)

        # 发送响应
        conn.send(tlv_packet)

        print("退出响应已发送.")

    def encode_tlv(self, data):
        """编码数据为TLV格式"""
        json_data = json.dumps(data).encode('utf-8') + b'\n'  # 加入换行符
        length = len(json_data)
        # 使用大端字节序编码长度
        length_header = struct.pack('>I', length)
        return length_header + json_data

    def start(self):
        """启动服务器并接受多个客户端连接"""
        print("等待客户端连接...")
        while True:
            conn, addr = self.server.accept()  # 等待并接受新的客户端连接
            # 为每个连接创建一个新线程处理
            client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    server = SimpleServer()
    server.start()
