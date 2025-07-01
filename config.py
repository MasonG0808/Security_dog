# 服务器配置
SERVER_CONFIG = {
    # 服务器基础URL - 请修改为您的实际服务器地址
    "base_url": "https://yourserver.com",  # 修改为您的服务器地址
    "ws_url": "ws://yourserver.com/ws",    # WebSocket连接地址
    
    # API端点 (FastAPI风格)
    "endpoints": {
        "health": "/health",                           # 健康检查
        "register_session": "/api/session/register",   # 注册会话
        "check_approval": "/api/session/check/{session_id}", # 检查用户确认状态
        "encryption_completed": "/api/encryption/completed", # 通知加密完成
        "get_key": "/api/key/get",                     # 获取密钥
        "decrypt_key": "/api/key/decrypt/{user_id}",   # 解密密钥
        "get_public_key": "/api/key/public/{user_id}", # 获取公钥
        "websocket": "/ws",                            # WebSocket连接
    },
    
    # 连接设置
    "timeout": 5,  # HTTP连接超时时间（秒）
    "ws_timeout": 10,  # WebSocket连接超时时间（秒）
    "retry_count": 3,  # 重试次数
    "heartbeat_interval": 30,  # 心跳包间隔（秒）
}

# 加密配置
ENCRYPTION_CONFIG = {
    "chunk_size": 1024 * 1024,  
    "key_size": 32,  # AES-256
    "rsa_key_size": 2048,
    "max_workers": None,  # 多进程工作进程数，None表示使用CPU核心数
    "process_timeout": 300,  # 进程超时时间（秒）
}

# 界面配置
UI_CONFIG = {
    "window_title": "文件自动加密系统",
    "window_size": (800, 600),
    "qr_size": (300, 300),
} 