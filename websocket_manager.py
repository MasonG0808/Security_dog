import asyncio
import json
import time
import threading
from typing import Optional, Callable, Dict, Any
import websockets
from PyQt5.QtCore import QObject, pyqtSignal, QThread

try:
    from config import SERVER_CONFIG
except ImportError:
    SERVER_CONFIG = {
        "ws_url": "ws://yourserver.com/ws",
        "ws_timeout": 10,
        "heartbeat_interval": 30,
    }

class WebSocketManager(QObject):
    """WebSocket连接管理器，支持心跳包和异步通信"""
    
    # 定义信号
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    message_received = pyqtSignal(str)  # 接收到的消息
    error_occurred = pyqtSignal(str)    # 错误信息
    
    def __init__(self):
        super().__init__()
        self.websocket = None
        self.is_connected = False
        self.heartbeat_task = None
        self.receive_task = None
        self.loop = None
        self.thread = None
        self.message_handlers: Dict[str, Callable] = {}
        
    def start(self):
        """启动WebSocket连接"""
        if self.thread is None or not self.thread.isRunning():
            self.thread = WebSocketThread(self)
            self.thread.connected.connect(self.on_connected)
            self.thread.disconnected.connect(self.on_disconnected)
            self.thread.message_received.connect(self.on_message_received)
            self.thread.error_occurred.connect(self.on_error_occurred)
            self.thread.start()
    
    def stop(self):
        """停止WebSocket连接"""
        if self.thread and self.thread.isRunning():
            self.thread.stop()
            self.thread.wait()
    
    def send_message(self, message_type: str, data: Dict[str, Any] = None):
        """发送消息到服务器"""
        if self.thread and self.thread.isRunning():
            message = {
                "type": message_type,
                "timestamp": int(time.time()),
                "data": data or {}
            }
            self.thread.send_message(json.dumps(message))
    
    def register_handler(self, message_type: str, handler: Callable):
        """注册消息处理器"""
        self.message_handlers[message_type] = handler
    
    def on_connected(self):
        """连接成功回调"""
        self.is_connected = True
        self.connected.emit()
        print("WebSocket连接成功")
    
    def on_disconnected(self):
        """连接断开回调"""
        self.is_connected = False
        self.disconnected.emit()
        print("WebSocket连接断开")
    
    def on_message_received(self, message_str: str):
        """接收消息回调"""
        try:
            message = json.loads(message_str)
            message_type = message.get("type")
            
            if message_type in self.message_handlers:
                self.message_handlers[message_type](message.get("data", {}))
            else:
                print(f"未处理的消息类型: {message_type}")
                
            self.message_received.emit(message_str)
        except json.JSONDecodeError as e:
            self.error_occurred.emit(f"消息解析错误: {e}")
    
    def on_error_occurred(self, error: str):
        """错误回调"""
        self.error_occurred.emit(error)
        print(f"WebSocket错误: {error}")

class WebSocketThread(QThread):
    """WebSocket工作线程"""
    
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    message_received = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, manager: WebSocketManager):
        super().__init__()
        self.manager = manager
        self.running = False
        self.websocket = None
        self.loop = None
        self.message_queue = asyncio.Queue()
    
    def run(self):
        """运行WebSocket连接"""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.running = True
            
            # 启动WebSocket连接
            self.loop.run_until_complete(self.connect_websocket())
            
        except Exception as e:
            self.error_occurred.emit(f"WebSocket线程错误: {e}")
        finally:
            self.running = False
    
    async def connect_websocket(self):
        """连接WebSocket"""
        try:
            uri = SERVER_CONFIG["ws_url"]
            self.websocket = await websockets.connect(
                uri, 
                ping_interval=20, 
                ping_timeout=10,
                close_timeout=10
            )
            
            self.connected.emit()
            
            # 启动心跳任务
            heartbeat_task = asyncio.create_task(self.heartbeat_loop())
            receive_task = asyncio.create_task(self.receive_loop())
            send_task = asyncio.create_task(self.send_loop())
            
            # 等待任务完成
            await asyncio.gather(heartbeat_task, receive_task, send_task)
            
        except Exception as e:
            self.error_occurred.emit(f"WebSocket连接失败: {e}")
        finally:
            if self.websocket:
                await self.websocket.close()
            self.disconnected.emit()
    
    async def heartbeat_loop(self):
        """心跳包循环"""
        while self.running and self.websocket:
            try:
                heartbeat_msg = {
                    "type": "heartbeat",
                    "timestamp": int(time.time()),
                    "data": {"client_id": "pc_client"}
                }
                await self.websocket.send(json.dumps(heartbeat_msg))
                await asyncio.sleep(SERVER_CONFIG["heartbeat_interval"])
            except Exception as e:
                self.error_occurred.emit(f"心跳包发送失败: {e}")
                break
    
    async def receive_loop(self):
        """接收消息循环"""
        while self.running and self.websocket:
            try:
                message = await self.websocket.recv()
                self.message_received.emit(message)
            except websockets.exceptions.ConnectionClosed:
                break
            except Exception as e:
                self.error_occurred.emit(f"接收消息失败: {e}")
                break
    
    async def send_loop(self):
        """发送消息循环"""
        while self.running and self.websocket:
            try:
                # 从队列中获取消息
                message = await asyncio.wait_for(
                    self.message_queue.get(), 
                    timeout=1.0
                )
                await self.websocket.send(message)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.error_occurred.emit(f"发送消息失败: {e}")
                break
    
    def send_message(self, message: str):
        """发送消息（线程安全）"""
        if self.loop and self.running:
            asyncio.run_coroutine_threadsafe(
                self.message_queue.put(message), 
                self.loop
            )
    
    def stop(self):
        """停止线程"""
        self.running = False
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop) 