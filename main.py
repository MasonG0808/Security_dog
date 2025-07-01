import os
import json
import time
import qrcode
import requests
import multiprocessing
import concurrent.futures
import numpy as np
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import uuid
import base64
import ctypes
import pickle
from functools import partial

# 导入配置文件
try:
    from config import SERVER_CONFIG, ENCRYPTION_CONFIG
except ImportError:
    # 如果配置文件不存在，使用默认配置
    SERVER_CONFIG = {
        "base_url": "https://yourserver.com",
        "ws_url": "ws://yourserver.com/ws",
        "endpoints": {
            "health": "/health",
            "register_session": "/api/session/register",
            "check_approval": "/api/session/check/{session_id}",
            "encryption_completed": "/api/encryption/completed",
            "get_key": "/api/key/get",
            "decrypt_key": "/api/key/decrypt/{user_id}",
            "get_public_key": "/api/key/public/{user_id}",
            "websocket": "/ws",
        },
        "timeout": 5,
        "ws_timeout": 10,
        "retry_count": 3,
        "heartbeat_interval": 30,
    }
    ENCRYPTION_CONFIG = {
        "chunk_size": 1024 * 1024,
        "key_size": 32,
        "rsa_key_size": 2048,
        "max_workers": None,
        "process_timeout": 300,
    }

try:
    import aesni
    HAS_AESNI = True
except ImportError:
    HAS_AESNI = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# 检测并加载加速库
ACCEL_LIB_DIR = os.path.join(os.path.dirname(__file__), 'accel_libs')
CUDA_DLL = os.path.join(ACCEL_LIB_DIR, 'cuda', 'aes_cuda.dll')
OPENCL_DLL = os.path.join(ACCEL_LIB_DIR, 'opencl', 'aes_opencl.dll')

HAS_CUDA_LIB = os.path.exists(CUDA_DLL)
HAS_OPENCL_LIB = os.path.exists(OPENCL_DLL)

if HAS_CUDA_LIB:
    cuda_lib = ctypes.CDLL(CUDA_DLL)
    def encrypt_chunk_cuda(chunk_data, key, iv):
        in_buf = (ctypes.c_ubyte * len(chunk_data)).from_buffer_copy(chunk_data)
        out_buf = (ctypes.c_ubyte * len(chunk_data))()
        key_buf = (ctypes.c_ubyte * 16).from_buffer_copy(key)
        iv_buf = (ctypes.c_ubyte * 16).from_buffer_copy(iv)
        cuda_lib.aes_encrypt_cbc(in_buf, out_buf, ctypes.c_int(len(chunk_data)), key_buf, iv_buf)
        return bytes(out_buf)
else:
    def encrypt_chunk_cuda(chunk_data, key, iv):
        return None

if HAS_OPENCL_LIB:
    opencl_lib = ctypes.CDLL(OPENCL_DLL)
    def encrypt_chunk_opencl(chunk_data, key, iv):
        in_buf = (ctypes.c_ubyte * len(chunk_data)).from_buffer_copy(chunk_data)
        out_buf = (ctypes.c_ubyte * len(chunk_data))()
        key_buf = (ctypes.c_ubyte * 16).from_buffer_copy(key)
        iv_buf = (ctypes.c_ubyte * 16).from_buffer_copy(iv)
        opencl_lib.aes_encrypt_cbc(in_buf, out_buf, ctypes.c_int(len(chunk_data)), key_buf, iv_buf)
        return bytes(out_buf)
else:
    def encrypt_chunk_opencl(chunk_data, key, iv):
        return None

# --- 生成二维码（唯一保留） ---
def generate_qr_code(file_path, session_id):
    """
    生成包含文件信息和session_id的二维码
    file_path: 文件路径
    session_id: 会话ID
    返回: 生成的二维码图片路径
    """
    try:
        import os, time, json, qrcode
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        qr_info = {
            "file_path": file_path,
            "file_name": file_name,
            "file_size": file_size,
            "session_id": session_id,
            "timestamp": int(time.time())
        }
        data = json.dumps(qr_info, ensure_ascii=False)
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        qr_path = f"qr_session_{session_id}.png"
        img.save(qr_path)
        return qr_path
    except Exception as e:
        print(f"生成二维码时出错: {e}")
        # 返回一个默认的二维码路径，避免程序崩溃
        return "qr_error.png"

# --- 获取机器唯一ID ---
def get_machine_id():
    """获取当前机器的唯一标识符"""
    try:
        if os.name == 'nt':  # Windows
            import winreg
            registry = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
            key = winreg.OpenKey(registry, r"SOFTWARE\Microsoft\Cryptography")
            machine_guid = winreg.QueryValueEx(key, "MachineGuid")[0]
            return machine_guid
        elif os.name == 'posix':  # Linux, macOS
            with open('/etc/machine-id', 'r') as f:
                return f.read().strip()
        else:
            # 备选方案，根据主机名和MAC地址生成
            import uuid
            return str(uuid.getnode())
    except:
        # 如果上述方法都失败，使用随机UUID
        return str(uuid.uuid4())


# --- 轮询服务器检查用户确认状态 ---
def poll_server_for_approval(session_id, timeout=60, interval=2):
    """
    轮询服务器检查用户是否已通过移动端确认加密操作
    session_id: 会话ID
    timeout: 超时时间(秒)
    interval: 轮询间隔(秒)
    返回: (approved, symmetric_key) 元组，approved为布尔值，symmetric_key为对称密钥
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            url = f"{SERVER_CONFIG['base_url']}{SERVER_CONFIG['endpoints']['check_approval']}/{session_id}"
            response = requests.get(url, timeout=SERVER_CONFIG['timeout'])
            
            if response.status_code == 200:
                data = response.json()
                if data.get("approved", False):
                    # 如果用户已确认，获取对称密钥
                    symmetric_key = bytes.fromhex(data.get("symmetric_key", ""))
                    salt = bytes.fromhex(data.get("salt", "")) if data.get("salt") else None
                    return True, symmetric_key, salt
                    
            # 等待下一次轮询
            time.sleep(interval)
            
        except Exception as e:
            print(f"轮询服务器时出错: {e}")
            time.sleep(interval)
    
    # 超时返回未确认
    return False, None, None

# --- 改进加密流程，配合移动端确认 ---
def aes_encrypt_file_with_mobile_confirmation(file_path, progress_callback=None, acceleration_method=None, thread_count=None):
    """
    通过移动端确认后对文件进行加密，密钥只从服务器获取
    file_path: 要加密的文件路径
    progress_callback: 进度回调函数
    acceleration_method: 加速方式
    thread_count: 线程数
    """
    try:
        # 生成带会话ID的二维码
        qr_path = generate_qr_code(file_path, 3344)#session_id
        
        # 提示用户扫描二维码
        print(f"请使用移动端扫描二维码确认加密操作: {qr_path}")
        
        if progress_callback:
            progress_callback(5)  # 生成二维码完成，进度5%
        
        # 轮询服务器等待用户确认
        confirmed, symmetric_key, salt = poll_server_for_approval(session_id)
        
        if not confirmed or symmetric_key is None:
            print("用户未在规定时间内确认加密操作或服务器未返回密钥，操作已取消")
            if progress_callback:
                progress_callback(0)  # 重置进度条
            return None
        
        if progress_callback:
            progress_callback(10)  # 用户确认完成，进度10%
        
        # 如果用户已确认且获取了对称密钥，进行加密
        print("用户已确认加密操作，服务器已提供加密密钥，开始加密...")
        
        # 调用原有的加密函数完成加密，不允许生成随机密钥
        encrypted_file_path = aes_encrypt_file(
            file_path, 
            symmetric_key=symmetric_key,  # 只使用从服务器获取的密钥
            progress_callback=lambda p: progress_callback(10 + int(p * 0.9)) if progress_callback else None,  # 调整进度比例
            acceleration_method=acceleration_method,
            thread_count=thread_count
            # 明确不传递password参数，确保只使用服务器提供的密钥
        )
        
        # 加密失败检查
        if encrypted_file_path is None:
            print("加密过程失败")
            if progress_callback:
                progress_callback(0)  # 重置进度条
            return None
            
        # 通知服务器加密已完成
        notify_encryption_completed(session_id, encrypted_file_path)
        
        return encrypted_file_path
        
    except Exception as e:
        print(f"带移动端确认的加密过程中出错: {e}")
        if progress_callback:
            progress_callback(0)  # 重置进度条
        return None

# --- 通知服务器加密已完成 ---
def notify_encryption_completed(session_id, encrypted_file_path):
    """通知服务器加密已完成"""
    try:
        file_name = os.path.basename(encrypted_file_path)
        file_size = os.path.getsize(encrypted_file_path)
        
        url = f"{SERVER_CONFIG['base_url']}{SERVER_CONFIG['endpoints']['encryption_completed']}"
        response = requests.post(
            url,
            json={
                "session_id": session_id,
                "encrypted_file_name": file_name,
                "encrypted_file_size": file_size,
                "status": "completed",
                "timestamp": int(time.time())
            },
            timeout=SERVER_CONFIG['timeout']
        )
        
        if response.status_code == 200:
            print("已通知服务器加密完成")
            return True
        else:
            print(f"通知服务器失败，状态码: {response.status_code}")
            return False
    except Exception as e:
        print(f"通知服务器时出错: {e}")
        return False

# --- 模拟与服务器通信，获取对称密钥 ---
def get_symmetric_key_from_server(file_info, rsa_public_key):
    """
    模拟使用RSA公钥加密请求信息后发送给服务器,
    服务器端解密并生成对称密钥返回.
    """
    try:
        # 使用RSA公钥加密请求数据
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        request_data = json.dumps(file_info).encode('utf-8')
        encrypted_request = cipher_rsa.encrypt(request_data)
        
        # 发送加密数据到服务器
        url = f"{SERVER_CONFIG['base_url']}{SERVER_CONFIG['endpoints']['get_key']}"
        response = requests.post(url, data=encrypted_request, timeout=SERVER_CONFIG['timeout'])
        
        # 假设服务器返回明文对称密钥（实际场景中可能需要进一步的RSA解密）
        symmetric_key = response.content  
        return symmetric_key
    except Exception as e:
        print("与服务器通信出错:", e)
        return None

# --- 使用CUDA加速加密数据块 ---
def encrypt_chunk_cuda(chunk_data, key, iv):
    """使用CUDA加速加密数据块"""
    if not HAS_CUDA_LIB:
        return None
    
    try:
        # 确保数据长度是16的倍数（AES块大小）
        padded_data = pad(chunk_data, AES.block_size)
        data_len = len(padded_data)
        
        # 创建输入和输出缓冲区
        data_gpu = cuda_lib.malloc(data_len)
        key_gpu = cuda_lib.malloc(len(key))
        iv_gpu = cuda_lib.malloc(len(iv))
        result_gpu = cuda_lib.malloc(data_len)
        
        # 将数据复制到GPU
        cuda_lib.memcpy_htod(data_gpu, padded_data)
        cuda_lib.memcpy_htod(key_gpu, key)
        cuda_lib.memcpy_htod(iv_gpu, iv)
        
        # 计算网格和块大小
        block_size = 256
        grid_size = (data_len + block_size - 1) // block_size
        
        # 执行加密
        cuda_lib.aes_encrypt_cbc(data_gpu, result_gpu, ctypes.c_int(data_len), key_gpu, iv_gpu)
        
        # 获取结果
        result = bytearray(data_len)
        cuda_lib.memcpy_dtoh(result, result_gpu)
        
        # 释放GPU内存
        cuda_lib.free(data_gpu)
        cuda_lib.free(key_gpu)
        cuda_lib.free(iv_gpu)
        cuda_lib.free(result_gpu)
        
        return bytes(result)
    except Exception as e:
        print(f"CUDA加密出错: {e}")
        return None

# --- 使用OpenCL加速加密数据块 ---
def encrypt_chunk_opencl(chunk_data, key, iv):
    """使用OpenCL加速加密数据块"""
    if not HAS_OPENCL_LIB:
        return None
    
    try:
        # 确保数据长度是16的倍数（AES块大小）
        padded_data = pad(chunk_data, AES.block_size)
        data_len = len(padded_data)
        
        # 创建输入和输出缓冲区
        data_cl = opencl_lib.malloc(data_len)
        key_cl = opencl_lib.malloc(len(key))
        iv_cl = opencl_lib.malloc(len(iv))
        result_cl = opencl_lib.malloc(data_len)
        
        # 将数据复制到GPU
        opencl_lib.memcpy_htod(data_cl, padded_data)
        opencl_lib.memcpy_htod(key_cl, key)
        opencl_lib.memcpy_htod(iv_cl, iv)
        
        # 执行加密
        global_size = (data_len // 16,)
        local_size = None  # 让OpenCL自动选择
        
        opencl_lib.aes_encrypt_cbc(data_cl, result_cl, ctypes.c_int(data_len), key_cl, iv_cl)
        
        # 获取结果
        result = np.zeros(data_len, dtype=np.uint8)
        opencl_lib.memcpy_dtoh(result, result_cl)
        
        # 释放GPU内存
        opencl_lib.free(data_cl)
        opencl_lib.free(key_cl)
        opencl_lib.free(iv_cl)
        opencl_lib.free(result_cl)
        
        return bytes(result)
    except Exception as e:
        print(f"OpenCL加密出错: {e}")
        return None

# --- 使用AES-NI硬件加速加密块数据 ---
def encrypt_chunk_aesni(chunk, key, iv):
    """使用AES-NI指令集加密数据块"""
    try:
        if HAS_AESNI:
            # 使用aesni库进行加密
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(chunk) + padder.finalize()
            return aesni.encrypt(padded_data, key, iv)
        else:
            # 回退到PyCryptodome
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return cipher.encrypt(pad(chunk, AES.block_size))
    except Exception as e:
        print(f"AES-NI加密出错: {e}")
        # 回退到PyCryptodome
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(chunk, AES.block_size))

# --- 使用cryptography库的硬件加速加密块数据 ---
def encrypt_chunk_cryptography(chunk, key, iv):
    """使用cryptography库加密数据块,可能会利用OpenSSL的硬件加速"""
    try:
        if HAS_CRYPTOGRAPHY:
            # 使用cryptography库进行加密
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(chunk) + padder.finalize()
            encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
            return encryptor.update(padded_data) + encryptor.finalize()
        else:
            # 回退到PyCryptodome
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return cipher.encrypt(pad(chunk, AES.block_size))
    except Exception as e:
        print(f"cryptography加密出错: {e}")
        # 回退到PyCryptodome
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(chunk, AES.block_size))

# --- 加密单个数据块 ---
def encrypt_chunk(chunk_data, key, iv, chunk_index):
    """加密单个数据块,选择最佳可用的加密方法"""
    try:
        # 为每个块使用不同的IV（通过XOR操作原始IV和块索引）
        block_iv = bytes(x ^ y for x, y in zip(iv, chunk_index.to_bytes(16, byteorder='big')))
        
        # 尝试使用GPU加速
        if HAS_CUDA_LIB:
            encrypted_chunk = encrypt_chunk_cuda(chunk_data, key, block_iv)
            if encrypted_chunk:
                return (chunk_index, encrypted_chunk, block_iv)
        
        if HAS_OPENCL_LIB:
            encrypted_chunk = encrypt_chunk_opencl(chunk_data, key, block_iv)
            if encrypted_chunk:
                return (chunk_index, encrypted_chunk, block_iv)
        
        # 尝试使用CPU硬件加速
        if HAS_AESNI:
            encrypted_chunk = encrypt_chunk_aesni(chunk_data, key, block_iv)
        elif HAS_CRYPTOGRAPHY:
            encrypted_chunk = encrypt_chunk_cryptography(chunk_data, key, block_iv)
        else:
            # 使用PyCryptodome
            cipher = AES.new(key, AES.MODE_CBC, block_iv)
            encrypted_chunk = cipher.encrypt(pad(chunk_data, AES.block_size))
        
        return (chunk_index, encrypted_chunk, block_iv)
    except Exception as e:
        print(f"加密数据块 {chunk_index} 时出错: {e}")
        return None

# --- 使用AES对文件进行加密（带硬件加速和多进程）---
def aes_encrypt_file(file_path, user_id, progress_callback=None, acceleration_method=None, thread_count=None, password=None):
    """
    对指定文件使用AES CBC模式进行加密，并保存为 .enc 文件
    支持多进程并行加密
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            print(f"文件不存在: {file_path}")
            return None
        
        # 1. 获取服务器公钥
        try:
            rsa_public_key = get_user_public_key_from_server(user_id)
            if rsa_public_key is None:
                print("无法获取服务器公钥，使用本地加密模式")
                # 如果无法获取服务器公钥，使用本地加密模式
                return encrypt_locally(file_path, password, progress_callback)
        except Exception as e:
            print(f"获取服务器公钥失败: {e}，使用本地加密模式")
            return encrypt_locally(file_path, password, progress_callback)
        
        # 2. 本地生成对称密钥
        symmetric_key, salt = generate_custom_symmetric_key(password)
        
        # 3. 用公钥加密对称密钥
        encrypted_key = encrypt_symmetric_key(symmetric_key, salt, rsa_public_key)
        if encrypted_key is None:
            print("加密对称密钥失败")
            return None
        
        # 4. 生成随机IV
        iv = os.urandom(16)
        
        # 5. 获取文件大小
        file_size = os.path.getsize(file_path)
        chunk_size = ENCRYPTION_CONFIG["chunk_size"]
        
        # 6. 确定进程数
        max_workers = ENCRYPTION_CONFIG["max_workers"]
        if max_workers is None:
            max_workers = multiprocessing.cpu_count()
        if thread_count:
            max_workers = min(max_workers, thread_count)
        
        print(f"使用 {max_workers} 个进程进行加密")
        
        # 7. 读取文件分块
        chunks = []
        try:
            with open(file_path, 'rb') as in_file:
                chunk_index = 0
                while True:
                    chunk = in_file.read(chunk_size)
                    if not chunk:
                        break
                    chunks.append((chunk, chunk_index))
                    chunk_index += 1
        except Exception as e:
            print(f"读取文件失败: {e}")
            return None
        
        total_chunks = len(chunks)
        
        # 8. 使用多进程并行加密
        encrypted_file_path = file_path + ".enc"
        
        try:
            with open(encrypted_file_path, 'wb') as out_file:
                # 写入文件头
                out_file.write(iv)
                out_file.write(file_size.to_bytes(8, byteorder='big'))
                
                # 使用进程池进行并行加密
                with multiprocessing.Pool(processes=max_workers) as pool:
                    # 准备加密任务
                    encrypt_tasks = []
                    for chunk, index in chunks:
                        task = pool.apply_async(
                            encrypt_chunk_process, 
                            (chunk, symmetric_key, iv, index, acceleration_method)
                        )
                        encrypt_tasks.append((index, task))
                    
                    # 收集加密结果
                    encrypted_chunks = {}
                    completed_chunks = 0
                    
                    for index, task in encrypt_tasks:
                        try:
                            result = task.get(timeout=ENCRYPTION_CONFIG["process_timeout"])
                            if result:
                                chunk_index, encrypted_chunk, _ = result
                                encrypted_chunks[chunk_index] = encrypted_chunk
                            completed_chunks += 1
                            
                            if progress_callback:
                                progress_percent = int(completed_chunks * 100 / total_chunks)
                                progress_callback(progress_percent)
                                
                        except Exception as e:
                            print(f"加密块 {index} 失败: {e}")
                            return None
                    
                    # 按顺序写入加密数据
                    for i in range(len(chunks)):
                        if i in encrypted_chunks:
                            out_file.write(encrypted_chunks[i])
                        else:
                            print(f"缺少加密块 {i}")
                            return None
                
                # 写入加密后的对称密钥长度
                out_file.write(len(encrypted_key).to_bytes(4, byteorder='big'))
                # 写入加密后的对称密钥
                out_file.write(encrypted_key)
                # 写入标记
                out_file.write(b"ENCRYPTED")
            
            print(f"文件已加密，保存为: {encrypted_file_path}")
            return encrypted_file_path
            
        except Exception as e:
            print(f"写入加密文件失败: {e}")
            return None
        
    except Exception as e:
        print("加密过程中出错:", e)
        return None

def encrypt_locally(file_path, password, progress_callback=None):
    """本地加密模式，不依赖服务器"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        import os
        
        # 生成随机密钥
        key = os.urandom(32)
        iv = os.urandom(16)
        
        # 读取原文件
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # 加密数据
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        
        # 保存加密文件
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            f.write(iv)
            f.write(len(data).to_bytes(8, byteorder='big'))
            f.write(encrypted_data)
            f.write(key)  # 简单保存密钥（实际应用中应该加密保存）
            f.write(b"LOCAL_ENCRYPTED")
        
        if progress_callback:
            progress_callback(100)
        
        print(f"本地加密完成: {encrypted_file_path}")
        return encrypted_file_path
        
    except Exception as e:
        print(f"本地加密失败: {e}")
        return None

# 生成RSA密钥对
def generate_rsa_key_pair():
    try:
        rsa_key = RSA.generate(2048)
        rsa_public_key = rsa_key.publickey()
        return rsa_key, rsa_public_key
    except Exception as e:
        print(f"生成RSA密钥对失败: {e}")
        return None, None

# 获取可用的加速方式
def get_available_acceleration_methods():
    try:
        methods = []
        if HAS_CUDA_LIB:
            methods.append("CUDA GPU加速")
        if HAS_OPENCL_LIB:
            methods.append("OpenCL GPU加速")
        if HAS_CRYPTOGRAPHY:
            methods.append("OpenSSL加速")
        if not methods:
            methods.append("标准加密（无硬件加速）")
        return methods
    except Exception as e:
        print(f"获取加速方式失败: {e}")
        return ["标准加密（无硬件加速）"]

# --- 生成自定义对称密钥 ---
def generate_custom_symmetric_key(password=None, key_size=32):
    """
    生成自定义对称密钥
    password: 用户提供的密码，如果为None则生成随机密钥
    key_size: 密钥大小（字节），默认为32（AES-256）
    """
    try:
        if password:
            # 使用密码派生密钥
            from Crypto.Protocol.KDF import PBKDF2
            from Crypto.Hash import SHA256
            salt = os.urandom(16)
            key = PBKDF2(password, salt, dkLen=key_size, count=1000000, hmac_hash_module=SHA256)
            return key, salt
        else:
            # 生成随机密钥
            return os.urandom(key_size), None
    except Exception as e:
        print(f"生成对称密钥失败: {e}")
        return None, None

# --- 使用RSA加密对称密钥 ---
def encrypt_symmetric_key(symmetric_key, salt, rsa_public_key):
    """
    使用RSA公钥加密对称密钥
    symmetric_key: 对称密钥
    salt: 盐值（如果有）
    rsa_public_key: RSA公钥
    """
    try:
        # 创建RSA加密器
        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        
        # 准备要加密的数据（密钥和盐值）
        data = {
            "key": symmetric_key.hex(),
            "salt": salt.hex() if salt else None
        }
        
        # 加密数据
        encrypted_data = cipher_rsa.encrypt(json.dumps(data).encode('utf-8'))
        return encrypted_data
    except Exception as e:
        print("加密对称密钥出错:", e)
        return None

# --- 解密文件 ---
def aes_decrypt_file(encrypted_file_path, user_id, progress_callback=None):
    """
    解密使用AES CBC模式加密的文件
    1. 读取文件尾部的加密密钥密文，发送给服务器，服务器用私钥解密后返回对称密钥
    2. 用该密钥解密文件内容
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(encrypted_file_path):
            print(f"加密文件不存在: {encrypted_file_path}")
            return None
        
        # 检查是否为本地加密文件
        try:
            with open(encrypted_file_path, 'rb') as in_file:
                in_file.seek(0, os.SEEK_END)
                file_size = in_file.tell()
                in_file.seek(file_size - 15)
                if in_file.read(15) == b"LOCAL_ENCRYPTED":
                    # 本地加密文件
                    return decrypt_locally(encrypted_file_path, progress_callback)
        except:
            pass
        
        # 服务器加密文件
        try:
            with open(encrypted_file_path, 'rb') as in_file:
                iv = in_file.read(16)
                original_size = int.from_bytes(in_file.read(8), byteorder='big')
                in_file.seek(0, os.SEEK_END)
                file_size = in_file.tell()
                in_file.seek(file_size - 9)
                if in_file.read(9) != b"ENCRYPTED":
                    raise ValueError("文件不是有效的加密文件")
                in_file.seek(file_size - 13)
                key_length = int.from_bytes(in_file.read(4), byteorder='big')
                in_file.seek(file_size - 13 - key_length)
                encrypted_key = in_file.read(key_length)
                encrypted_data_size = file_size - 24 - key_length - 9
        except Exception as e:
            print(f"读取加密文件头失败: {e}")
            return None
            
        # 1. 发送密钥密文到服务器，获取对称密钥
        try:
            symmetric_key, salt = get_symmetric_key_from_server_v2(user_id, encrypted_key)
            if symmetric_key is None:
                print("无法从服务器获取对称密钥，解密失败")
                return None
        except Exception as e:
            print(f"获取对称密钥失败: {e}")
            return None
            
        # 2. 解密文件内容
        decrypted_file_path = encrypted_file_path[:-4] if encrypted_file_path.endswith('.enc') else encrypted_file_path + '.dec'
        
        try:
            with open(encrypted_file_path, 'rb') as in_file, open(decrypted_file_path, 'wb') as out_file:
                in_file.seek(24)
                chunk_size = 1024 * 1024
                total_chunks = (encrypted_data_size + chunk_size - 1) // chunk_size
                completed_chunks = 0
                for chunk_index in range(total_chunks):
                    current_chunk_size = min(chunk_size, encrypted_data_size - chunk_index * chunk_size)
                    encrypted_chunk = in_file.read(current_chunk_size)
                    block_iv = bytes(x ^ y for x, y in zip(iv, chunk_index.to_bytes(16, byteorder='big')))
                    cipher = AES.new(symmetric_key, AES.MODE_CBC, block_iv)
                    decrypted_chunk = unpad(cipher.decrypt(encrypted_chunk), AES.block_size) if chunk_index == total_chunks - 1 else cipher.decrypt(encrypted_chunk)
                    out_file.write(decrypted_chunk)
                    completed_chunks += 1
                    if progress_callback:
                        progress_percent = int(completed_chunks * 100 / total_chunks)
                        progress_callback(progress_percent)
        except Exception as e:
            print(f"解密文件内容失败: {e}")
            return None
            
        print(f"文件已解密，保存为: {decrypted_file_path}")
        return decrypted_file_path
        
    except Exception as e:
        print(f"解密过程中出错: {e}")
        return None

def decrypt_locally(encrypted_file_path, progress_callback=None):
    """本地解密模式"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        
        with open(encrypted_file_path, 'rb') as f:
            iv = f.read(16)
            original_size = int.from_bytes(f.read(8), byteorder='big')
            encrypted_data = f.read(-15)  # 读取到LOCAL_ENCRYPTED标记之前
            f.seek(-15, os.SEEK_END)
            if f.read(15) != b"LOCAL_ENCRYPTED":
                raise ValueError("不是有效的本地加密文件")
            f.seek(-47, os.SEEK_END)  # 回到密钥位置
            key = f.read(32)
        
        # 解密数据
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        
        # 保存解密文件
        decrypted_file_path = encrypted_file_path[:-4] if encrypted_file_path.endswith('.enc') else encrypted_file_path + '.dec'
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)
        
        if progress_callback:
            progress_callback(100)
        
        print(f"本地解密完成: {decrypted_file_path}")
        return decrypted_file_path
        
    except Exception as e:
        print(f"本地解密失败: {e}")
        return None

# 新增：解密时从服务器获取对称密钥

def get_symmetric_key_from_server_v2(user_id, encrypted_key):
    """
    发送加密密钥密文到服务器，服务器用私钥解密后返回对称密钥
    """
    try:
        # base64编码密钥密文
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode()
        url = f"{SERVER_CONFIG['base_url']}{SERVER_CONFIG['endpoints']['decrypt_key']}/{user_id}"
        response = requests.post(
            url,
            json={"encrypted_key": encrypted_key_b64},
            headers={"Content-Type": "application/json"},
            timeout=SERVER_CONFIG['timeout']
        )
        if response.status_code == 200:
            data = response.json()
            symmetric_key = bytes.fromhex(data["symmetric_key"])
            salt = bytes.fromhex(data["salt"]) if data.get("salt") else None
            return symmetric_key, salt
        else:
            print(f"服务器返回错误: {response.status_code}")
            return None, None
    except Exception as e:
        print(f"获取对称密钥时出错: {e}")
        return None, None

# 新增：获取服务器公钥

def get_user_public_key_from_server(user_id):
    """从服务器获取用户RSA公钥（PEM格式）"""
    try:
        url = f"{SERVER_CONFIG['base_url']}{SERVER_CONFIG['endpoints']['get_public_key']}/{user_id}"
        response = requests.get(url, timeout=SERVER_CONFIG['timeout'])
        if response.status_code == 200:
            pubkey_pem = response.json()["public_key"]
            return RSA.import_key(pubkey_pem)
        else:
            print(f"获取公钥失败，状态码: {response.status_code}")
            return None
    except Exception as e:
        print(f"获取公钥时出错: {e}")
        return None

# 多进程加密函数
def encrypt_chunk_process(chunk_data, key, iv, chunk_index, acceleration_method=None):
    """在独立进程中加密数据块"""
    try:
        # 为每个块使用不同的IV（通过XOR操作原始IV和块索引）
        block_iv = bytes(x ^ y for x, y in zip(iv, chunk_index.to_bytes(16, byteorder='big')))
        
        # 根据加速方式选择加密方法
        if acceleration_method == "CUDA GPU加速" and HAS_CUDA_LIB:
            encrypted_chunk = encrypt_chunk_cuda(chunk_data, key, block_iv)
        elif acceleration_method == "OpenCL GPU加速" and HAS_OPENCL_LIB:
            encrypted_chunk = encrypt_chunk_opencl(chunk_data, key, block_iv)
        elif acceleration_method == "OpenSSL加速" and HAS_CRYPTOGRAPHY:
            encrypted_chunk = encrypt_chunk_cryptography(chunk_data, key, block_iv)
        elif acceleration_method == "AES-NI加速" and HAS_AESNI:
            encrypted_chunk = encrypt_chunk_aesni(chunk_data, key, block_iv)
        else:
            # 使用PyCryptodome
            cipher = AES.new(key, AES.MODE_CBC, block_iv)
            encrypted_chunk = cipher.encrypt(pad(chunk_data, AES.block_size))
        
        return (chunk_index, encrypted_chunk, block_iv)
    except Exception as e:
        print(f"进程加密块 {chunk_index} 时出错: {e}")
        return None

def decrypt_chunk_process(encrypted_chunk, key, iv, chunk_index, is_last_chunk=False):
    """在独立进程中解密数据块"""
    try:
        # 为每个块使用不同的IV
        block_iv = bytes(x ^ y for x, y in zip(iv, chunk_index.to_bytes(16, byteorder='big')))
        
        cipher = AES.new(key, AES.MODE_CBC, block_iv)
        decrypted_chunk = cipher.decrypt(encrypted_chunk)
        
        # 只有最后一个块需要去除填充
        if is_last_chunk:
            decrypted_chunk = unpad(decrypted_chunk, AES.block_size)
        
        return (chunk_index, decrypted_chunk)
    except Exception as e:
        print(f"进程解密块 {chunk_index} 时出错: {e}")
        return None
