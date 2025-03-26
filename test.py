from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import socket
import json
import struct
import base64
import threading
from datetime import datetime

# 常量定义
AES_KEY_SIZE = 32  # AES 密钥大小（32 字节）
AES_IV_SIZE = 16   # AES IV 大小（16 字节）

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


class AESUtils:
    """AES 加密与解密工具类"""

    @staticmethod
    def generate_aes_key_iv():
        """生成 AES 密钥和 IV"""
        aes_key = get_random_bytes(AES_KEY_SIZE)
        aes_iv = get_random_bytes(AES_IV_SIZE)
        return aes_key, aes_iv

    @staticmethod
    def encrypt_data(aes_key, aes_iv, data):
        """使用 AES 加密数据"""
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        return encrypted_data

    @staticmethod
    def decrypt_data(aes_key, aes_iv, encrypted_data):
        """使用 AES 解密数据"""
        cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data

    @staticmethod
    def base64_encode(data):
        """将字节数据编码为 Base64 字符串"""
        return base64.b64encode(data).decode('utf-8')

    @staticmethod
    def base64_decode(data):
        """将 Base64 字符串解码为字节数据"""
        return base64.b64decode(data)


class BusinessLogicHandler:
    """业务逻辑处理类"""

    @staticmethod
    def handle_login_response(conn, aes_key, aes_iv):
        """处理登录响应，返回加密的消息"""
        response_data = {
            "status": "success",
            "message": "Login successful",
            "timestamp": int(datetime.now().timestamp())
        }

        # 将响应内容转化为 JSON 字符串
        json_response = json.dumps(response_data, ensure_ascii=False).encode('utf-8')

        # 使用 AES 加密
        encrypted_data = AESUtils.encrypt_data(aes_key, aes_iv, json_response)

        # Base64 编码加密后的数据
        encoded_data = AESUtils.base64_encode(encrypted_data)

        # 构建响应数据
        response = {
            "id": 1002,
            "desc": "登录返回",
            "data": encoded_data  # 返回加密后的数据
        }

        return response


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
        aes_key, aes_iv = AESUtils.generate_aes_key_iv()

        try:
            while True:
                data = self.receive_tlv_data(conn)
                if data:
                    print(f"接收到数据来自 {addr}: {data}")

                    msg_id = data.get("id")
                    message_type = map_message_type(msg_id)

                    if msg_id == 10001:
                        # 处理10001消息，生成 AES 密钥和 IV 并返回
                        aes_combined = aes_key + aes_iv
                        encoded_data = AESUtils.base64_encode(aes_combined)
                        response = {
                            "id": 10002,
                            "data": encoded_data
                        }
                        self.send_response(conn, response)
                    elif message_type == MessageType.DummyLogin:
                        # 处理登录消息
                        response = BusinessLogicHandler.handle_login_response(conn, aes_key, aes_iv)
                        self.send_response(conn, response)
                    else:
                        print(f"未知的消息类型 {message_type} 来自 {addr}")
                else:
                    print(f"连接 {addr} 断开")
                    break
        finally:
            conn.close()
            print(f"连接关闭: {addr}")

    def send_response(self, conn, response):
        """发送响应数据"""
        tlv_packet = self.encode_tlv(response)
        conn.send(tlv_packet)
        print("响应已发送.")

    def encode_tlv(self, data):
        """编码数据为TLV格式"""
        json_data = json.dumps(data).encode('utf-8') + b'\n'  # 加入换行符
        length = len(json_data)
        # 使用大端字节序编码长度
        length_header = struct.pack('>I', length)
        return length_header + json_data

    def receive_tlv_data(self, conn):
        """读取TLV格式的数据: 先接收长度，再接收数据"""
        try:
            header = conn.recv(4)
            if len(header) < 4:
                return None  # 没有接收到完整的长度头
            length = struct.unpack('>I', header)[0]
            print(f"接收到的消息长度: {length}")
            data = b''
            while len(data) < length:
                packet = conn.recv(length - len(data))
                if not packet:
                    return None  # 如果没有数据了，断开连接
                data += packet
            print(f"接收到的原始数据: {data}")
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"接收或解析数据错误: {str(e)}")
            return None

    def start(self):
        """启动服务器并接受多个客户端连接"""
        print("等待客户端连接...")
        while True:
            conn, addr = self.server.accept()  # 等待并接受新的客户端连接
            client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            client_thread.start()



if __name__ == "__main__":
    server = SimpleServer()
    server.start()
