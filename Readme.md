# 文件自动加密系统

这是一个基于PyQt5的文件自动加密系统，支持硬件加速、多进程加密和服务器端密钥管理。

## 功能特性

- **自动文件监控**: 监控文件资源管理器中的文件，悬停3秒自动触发加密/解密
- **多种硬件加速**: 支持CUDA、OpenCL、AES-NI、OpenSSL硬件加速
- **多进程并行加密**: 充分利用多核CPU，大幅提升加密速度
- **WebSocket实时通信**: 支持心跳包和异步消息，低延迟通信
- **服务器端密钥管理**: 安全的密钥分发和用户确认机制
- **二维码交互**: 生成二维码供移动端扫描确认
- **实时进度显示**: 加密/解密进度实时更新
- **自动重连机制**: WebSocket连接断开时自动重连
- **本地加密模式**: 服务器不可用时自动切换到本地加密

## 系统要求

### 操作系统
- Windows 10/11 (推荐)
- 支持Windows API的文件监控功能

### 硬件要求
- **CPU**: 支持AES-NI指令集（推荐）
- **内存**: 至少4GB RAM，大文件加密建议8GB+
- **GPU**: 可选，支持CUDA或OpenCL（用于GPU加速）
- **存储**: 足够的磁盘空间存储加密文件

### Python环境
- Python 3.7+
- pip包管理器

## 安装依赖

### 自动安装
```bash
pip install -r requirements.txt
```

### 手动安装
```bash
pip install PyQt5>=5.15.0
pip install pycryptodome>=3.15.0
pip install qrcode>=7.3.1
pip install requests>=2.25.1
pip install numpy>=1.21.0
pip install pywin32>=300
pip install psutil>=5.8.0
pip install websockets>=10.0
pip install cryptography>=3.4.8
pip install pywinauto>=0.6.8
pip install aesni>=0.1.0
```

### 可选依赖（硬件加速）
- **CUDA**: 需要NVIDIA GPU和CUDA Toolkit
- **OpenCL**: 需要支持OpenCL的GPU和SDK
- **AES-NI**: 现代Intel/AMD CPU自动支持

## 配置服务器地址

**重要：在运行程序之前，请先修改服务器地址！**

1. 打开 `config.py` 文件
2. 修改 `SERVER_CONFIG` 中的服务器地址：

```python
SERVER_CONFIG = {
    "base_url": "https://your-actual-server.com",  # HTTP服务器地址
    "ws_url": "ws://your-actual-server.com/ws",    # WebSocket服务器地址
    # ... 其他配置
}
```

## 服务器架构要求

您的服务器需要支持以下架构：

### FastAPI服务器端点

#### HTTP端点
- **GET /health** - 健康检查
  - 返回: `{"status": "ok"}`
  
- **POST /api/session/register** - 注册加密会话
  - 请求体: `{"client_id": "pc_client"}`
  - 返回: `{"session_id": "uuid-string"}`

- **GET /api/session/check/{session_id}** - 检查用户确认状态
  - 返回: `{"approved": true, "symmetric_key": "hex-string", "salt": "hex-string"}`

- **POST /api/encryption/completed** - 通知加密完成
  - 请求体: `{"session_id": "uuid", "encrypted_file_name": "file.enc", "encrypted_file_size": 12345, "status": "completed", "timestamp": 1234567890}`

- **POST /api/key/get** - 获取加密密钥
  - 请求体: RSA加密的密钥请求数据
  - 返回: 对称密钥（二进制数据）

- **POST /api/key/decrypt/{user_id}** - 解密密钥
  - 请求体: `{"encrypted_key": "base64-string"}`
  - 返回: `{"symmetric_key": "hex-string", "salt": "hex-string"}`

- **GET /api/key/public/{user_id}** - 获取用户公钥
  - 返回: `{"public_key": "PEM-format-key"}`

#### WebSocket端点
- **WS /ws** - WebSocket连接
  - 支持心跳包和实时消息

### WebSocket消息格式
```json
{
    "type": "message_type",
    "timestamp": 1234567890,
    "data": {
        // 消息数据
    }
}
```

### 消息类型
- **heartbeat**: 心跳包
- **encryption_approved**: 加密请求被批准
- **encryption_rejected**: 加密请求被拒绝

## 运行程序

```bash
python app.py
```

## 使用说明

### 基本操作
1. 启动程序后，系统会自动连接WebSocket服务器
2. 在文件资源管理器中悬停文件3秒，会显示二维码弹窗
3. 使用移动端扫描二维码确认加密操作
4. 系统会使用多进程并行加密文件并保存为 `.enc` 文件

### 加密流程
1. 检测到文件悬停 → 生成二维码
2. 移动端扫描二维码 → 发送确认请求到服务器
3. 服务器验证 → 返回对称密钥
4. PC端接收密钥 → 多进程并行加密
5. 加密完成 → 保存 `.enc` 文件

### 解密流程
1. 检测到 `.enc` 文件悬停 → 提示加载RSA密钥
2. 加载RSA私钥 → 发送密钥密文到服务器
3. 服务器解密 → 返回对称密钥
4. PC端接收密钥 → 解密文件内容
5. 解密完成 → 保存原文件

### 设置选项
- **加速方式**: 选择CUDA、OpenCL、OpenSSL或标准加密
- **线程数**: 设置多进程加密的进程数量
- **密码**: 可选密码，用于密钥派生

## 文件结构

```
加密软件/
├── app.py                 # 主程序入口
├── gui.py                 # GUI界面实现（PyQt5）
├── main.py                # 核心加密逻辑（支持多进程）
├── websocket_manager.py   # WebSocket连接管理器
├── config.py              # 配置文件
├── requirements.txt       # Python依赖包列表
├── Readme.md             # 项目说明文档
├── accel_libs/           # 硬件加速库
│   ├── cuda/             # CUDA加速代码
│   └── opencl/           # OpenCL加速代码
├── templates/            # HTML模板
│   └── index.html        # 移动端页面模板
└── session.json          # 会话ID存储文件
```

## 性能优化

### 多进程加密
- 使用 `multiprocessing.Pool` 进行并行加密
- 支持可配置的进程数量（默认使用CPU核心数）
- 大文件自动分块处理，避免内存溢出

### 硬件加速
- **CUDA加速**: NVIDIA GPU，适用于大文件加密
- **OpenCL加速**: 支持多种GPU，跨平台兼容
- **AES-NI加速**: Intel/AMD CPU内置指令集
- **OpenSSL加速**: 利用OpenSSL的硬件优化

### 异步通信
- WebSocket提供低延迟的实时通信
- 自动心跳包保持连接活跃
- 连接断开时自动重连

### 可配置参数
- 块大小: `ENCRYPTION_CONFIG["chunk_size"]`
- 进程数: `ENCRYPTION_CONFIG["max_workers"]`
- 超时时间: `SERVER_CONFIG["timeout"]`
- 心跳间隔: `SERVER_CONFIG["heartbeat_interval"]`

## 错误处理和故障排除

### 常见问题

#### 1. 连接服务器失败
**症状**: 状态指示器显示灰色，日志显示连接错误
**解决方案**:
- 检查 `config.py` 中的服务器地址是否正确
- 确认服务器是否正常运行
- 检查网络连接和防火墙设置

#### 2. WebSocket连接断开
**症状**: 连接状态频繁变化
**解决方案**:
- 检查网络稳定性
- 调整 `heartbeat_interval` 参数
- 确认服务器WebSocket端点正常

#### 3. 加密速度慢
**症状**: 大文件加密时间过长
**解决方案**:
- 增加多进程数量
- 启用硬件加速（CUDA/OpenCL）
- 调整块大小参数

#### 4. 内存不足
**症状**: 程序崩溃或加密失败
**解决方案**:
- 减少多进程数量
- 减小块大小
- 增加系统内存

#### 5. 文件监控不工作
**症状**: 悬停文件无反应
**解决方案**:
- 确认程序以管理员权限运行
- 检查Windows API权限
- 重启文件资源管理器

### 日志文件
程序运行时会生成以下日志文件：
- `error_log.txt`: 错误日志
- `session.json`: 会话ID存储

### 调试模式
在 `config.py` 中可以启用调试模式：
```python
DEBUG_MODE = True
```

## 安全注意事项

1. **密钥管理**: RSA私钥必须安全保存，不要泄露给他人
2. **网络传输**: 所有密钥传输都经过RSA加密
3. **本地存储**: 加密文件包含加密的密钥，需要私钥才能解密
4. **会话管理**: 每个加密操作都有唯一的会话ID
5. **权限控制**: 建议以普通用户权限运行，避免权限过高

## 开发说明

### 扩展硬件加速
1. 在 `accel_libs/` 目录下添加新的加速库
2. 在 `main.py` 中添加检测和调用逻辑
3. 更新 `get_available_acceleration_methods()` 函数

### 添加新的消息类型
1. 在 `websocket_manager.py` 中注册新的消息处理器
2. 在服务器端实现对应的消息处理逻辑
3. 更新API文档

### 自定义加密算法
1. 修改 `main.py` 中的加密函数
2. 更新密钥生成和加密逻辑
3. 确保与服务器端兼容

## 许可证

本项目仅供学习和研究使用，请遵守相关法律法规。

## 技术支持

如遇到问题，请检查：
1. 依赖包是否正确安装
2. 服务器配置是否正确
3. 系统权限是否足够
4. 网络连接是否正常

---

**注意**: 首次运行时，系统会自动检测并尝试编译适合本机的加速库。如果编译失败，程序会自动回退到标准加密模式。

