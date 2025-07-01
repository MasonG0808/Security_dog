import sys
import os
import json
import time
import traceback
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtCore import QThread, pyqtSignal, QPoint, QTimer, Qt
import main
import multiprocessing
import win32gui
import win32api
import win32con
import ctypes
import win32process
import psutil
import pythoncom

# 导入配置文件
try:
    from config import SERVER_CONFIG
except ImportError:
    # 如果配置文件不存在，使用默认配置
    SERVER_CONFIG = {
        "base_url": "https://yourserver.com",
        "ws_url": "ws://yourserver.com/ws",
        "endpoints": {
            "health": "/health",
        },
        "timeout": 5,
    }

# 导入WebSocket管理器
try:
    from websocket_manager import WebSocketManager
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False
    print("警告: 未安装websockets库，将使用HTTP连接")

# --- 全局异常处理器 ---
def global_exception_handler(exctype, value, traceback_obj):
    """全局异常处理器，防止程序崩溃"""
    error_msg = f"未捕获的异常: {exctype.__name__}: {value}"
    print(error_msg)
    print("详细错误信息:")
    traceback.print_exception(exctype, value, traceback_obj)
    
    # 将错误信息写入日志文件
    try:
        with open("error_log.txt", "a", encoding='utf-8') as f:
            f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {error_msg}\n")
            traceback.print_exception(exctype, value, traceback_obj, file=f)
    except:
        pass

# 设置全局异常处理器
sys.excepthook = global_exception_handler

# --- Session ID 管理函数 ---
SESSION_FILE = "session.json"

def save_session_id(session_id):
    """保存session_id到本地文件"""
    try:
        with open(SESSION_FILE, "w", encoding='utf-8') as f:
            json.dump({"session_id": session_id}, f)
    except Exception as e:
        print(f"保存session_id失败: {e}")

def load_session_id():
    """从本地文件加载session_id"""
    try:
        if os.path.exists(SESSION_FILE):
            with open(SESSION_FILE, "r", encoding='utf-8') as f:
                data = json.load(f)
                return data.get("session_id")
    except Exception as e:
        print(f"加载session_id失败: {e}")
    return None

# --- 工作线程类 ---
class EncryptionThread(QThread):
    # 定义信号
    encryption_done = pyqtSignal(str)  # 加密完成信号
    encryption_failed = pyqtSignal(str)  # 加密失败信号
    qr_generated = pyqtSignal(str)     # 二维码生成完成信号
    encryption_progress = pyqtSignal(int)  # 加密进度信号
    encryption_status = pyqtSignal(str)  # 加密状态信号
    
    def __init__(self, file_path, acceleration_method=None, thread_count=None, password=None, session_id=None):
        super().__init__()
        self.file_path = file_path
        self.acceleration_method = acceleration_method
        self.thread_count = thread_count
        self.password = password
        self.session_id = session_id
        
    def run(self):
        try:
            # 发送状态更新
            self.encryption_status.emit("正在生成二维码...")
            
            # 生成二维码 - 使用已保存的session_id
            try:
                if self.session_id:
                    qr_path = main.generate_qr_code(self.file_path, self.session_id)
                else:
                    qr_path = main.generate_qr_code(self.file_path, "unknown-session")
                
                # 发送二维码路径信号
                self.qr_generated.emit(qr_path)
            except Exception as e:
                print(f"生成二维码失败: {str(e)}")
                self.encryption_status.emit(f"生成二维码失败: {str(e)}")
                self.encryption_failed.emit(f"生成二维码失败: {str(e)}")
                return
            
            # 发送状态更新
            self.encryption_status.emit("正在连接服务器...")
            
            # 检查服务器连接状态
            try:
                # 尝试连接服务器获取公钥
                rsa_public_key = main.get_user_public_key_from_server("default_user")
                if rsa_public_key is None:
                    self.encryption_status.emit("无法连接服务器，使用本地加密模式")
                    # 如果无法连接服务器，使用本地加密模式
                    self.encrypt_locally()
                    return
            except Exception as e:
                print(f"连接服务器失败: {str(e)}")
                self.encryption_status.emit("服务器连接失败，使用本地加密模式")
                # 如果连接失败，使用本地加密模式
                self.encrypt_locally()
                return
            
            # 发送状态更新
            self.encryption_status.emit("正在加密文件...")
            
            # 定义进度回调函数
            def progress_callback(progress):
                try:
                    self.encryption_progress.emit(progress)
                except Exception as e:
                    print(f"进度回调出错: {str(e)}")
            
            # 加密文件
            try:
                encrypted_file_path = main.aes_encrypt_file(
                    self.file_path, 
                    user_id="default_user",  # 添加缺失的user_id参数
                    progress_callback=progress_callback,
                    acceleration_method=self.acceleration_method,
                    thread_count=self.thread_count,
                    password=self.password  # 传递密码
                )
                
                # 检查加密结果
                if encrypted_file_path:
                    # 加密成功，发送成功信号
                    self.encryption_done.emit(encrypted_file_path)
                else:
                    # 加密失败，发送失败信号
                    self.encryption_failed.emit("加密过程返回空结果")
                    
            except Exception as e:
                print(f"加密文件时出错: {str(e)}")
                self.encryption_status.emit(f"加密失败: {str(e)}")
                self.encryption_failed.emit(str(e))
            
        except Exception as e:
            print(f"加密过程中出错: {str(e)}")
            print("详细错误信息:")
            traceback.print_exc()
            self.encryption_status.emit(f"加密失败: {str(e)}")
            # 发送失败信号
            self.encryption_failed.emit(str(e))
    
    def encrypt_locally(self):
        """本地加密模式，不依赖服务器"""
        try:
            self.encryption_status.emit("正在使用本地加密模式...")
            
            # 定义进度回调函数
            def progress_callback(progress):
                try:
                    self.encryption_progress.emit(progress)
                except Exception as e:
                    print(f"进度回调出错: {str(e)}")
            
            # 使用简单的本地加密
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            import os
            
            # 生成随机密钥
            key = os.urandom(32)
            iv = os.urandom(16)
            
            # 读取原文件
            with open(self.file_path, 'rb') as f:
                data = f.read()
            
            # 加密数据
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_data = cipher.encrypt(pad(data, AES.block_size))
            
            # 保存加密文件
            encrypted_file_path = self.file_path + ".enc"
            with open(encrypted_file_path, 'wb') as f:
                f.write(iv)
                f.write(len(data).to_bytes(8, byteorder='big'))
                f.write(encrypted_data)
                f.write(key)  # 简单保存密钥（实际应用中应该加密保存）
                f.write(b"LOCAL_ENCRYPTED")
            
            self.encryption_done.emit(encrypted_file_path)
            
        except Exception as e:
            print(f"本地加密失败: {str(e)}")
            self.encryption_status.emit(f"本地加密失败: {str(e)}")
            self.encryption_failed.emit(str(e))

class DecryptionThread(QThread):
    decryption_done = pyqtSignal(str)  # 解密完成信号
    decryption_failed = pyqtSignal(str)  # 解密失败信号
    decryption_progress = pyqtSignal(int)  # 解密进度信号
    decryption_status = pyqtSignal(str)  # 解密状态信号
    
    def __init__(self, file_path, rsa_private_key=None):
        super().__init__()
        self.file_path = file_path
        self.rsa_private_key = rsa_private_key
        
    def run(self):
        try:
            # 发送状态更新
            self.decryption_status.emit("正在解密文件...")
            
            # 定义进度回调函数
            def progress_callback(progress):
                try:
                    self.decryption_progress.emit(progress)
                except Exception as e:
                    print(f"进度回调出错: {str(e)}")
            
            # 解密文件
            try:
                decrypted_file_path = main.aes_decrypt_file(
                    self.file_path,
                    user_id="default_user",  # 添加缺失的user_id参数
                    progress_callback=progress_callback
                )
                
                # 检查解密结果
                if decrypted_file_path:
                    # 解密成功，发送成功信号
                    self.decryption_done.emit(decrypted_file_path)
                else:
                    # 解密失败，发送失败信号
                    self.decryption_failed.emit("解密过程返回空结果")
                    
            except Exception as e:
                print(f"解密文件时出错: {str(e)}")
                self.decryption_status.emit(f"解密失败: {str(e)}")
                self.decryption_failed.emit(str(e))
            
        except Exception as e:
            print(f"解密过程中出错: {str(e)}")
            print("详细错误信息:")
            traceback.print_exc()
            self.decryption_status.emit(f"解密失败: {str(e)}")
            # 发送失败信号
            self.decryption_failed.emit(str(e))

# --- PyQt5界面 ---
class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("加密设置")
        self.resize(400, 300)
        
        # 创建布局
        layout = QtWidgets.QVBoxLayout(self)
        
        # 加速方式选择
        self.acceleration_group = QtWidgets.QGroupBox("加速方式")
        acceleration_layout = QtWidgets.QVBoxLayout()
        
        # 获取可用的加速方式，异常保护
        try:
            self.acceleration_methods = main.get_available_acceleration_methods()
        except Exception as e:
            self.acceleration_methods = ["标准加密（无硬件加速）"]
            QtWidgets.QMessageBox.critical(self, "加速方式检测失败", f"检测加速方式时出错：{e}\n将使用默认加密方式。")
        
        # 创建单选按钮
        self.acceleration_radios = []
        for method in self.acceleration_methods:
            radio = QtWidgets.QRadioButton(method)
            self.acceleration_radios.append(radio)
            acceleration_layout.addWidget(radio)
        
        # 默认选中第一个
        if self.acceleration_radios:
            self.acceleration_radios[0].setChecked(True)
        
        self.acceleration_group.setLayout(acceleration_layout)
        layout.addWidget(self.acceleration_group)
        
        # 线程数设置
        thread_layout = QtWidgets.QHBoxLayout()
        thread_layout.addWidget(QtWidgets.QLabel("线程数:"))
        
        self.thread_spinbox = QtWidgets.QSpinBox()
        self.thread_spinbox.setMinimum(1)
        self.thread_spinbox.setMaximum(32)
        self.thread_spinbox.setValue(multiprocessing.cpu_count())
        thread_layout.addWidget(self.thread_spinbox)
        
        layout.addLayout(thread_layout)
        
        # 按钮
        button_layout = QtWidgets.QHBoxLayout()
        self.ok_button = QtWidgets.QPushButton("确定")
        self.cancel_button = QtWidgets.QPushButton("取消")
        
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        # 连接信号
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
    
    def get_selected_acceleration(self):
        """获取选中的加速方式"""
        for i, radio in enumerate(self.acceleration_radios):
            if radio.isChecked():
                return self.acceleration_methods[i]
        return None
    
    def get_thread_count(self):
        """获取线程数"""
        return self.thread_spinbox.value()

    def show_settings(self):
        try:
            dialog = SettingsDialog(self)
            if dialog.exec_() == QtWidgets.QDialog.Accepted:
                self.selected_acceleration = dialog.get_selected_acceleration()
                self.thread_count = dialog.get_thread_count()
                self.status_label.setText(f"设置已更新: {self.selected_acceleration}, {self.thread_count}线程")
        except Exception as e:
            import traceback
            traceback.print_exc()
            QtWidgets.QMessageBox.critical(self, "设置弹窗出错", f"设置弹窗出错:\n{e}")

# --- 二维码弹出窗口类 ---
class QRCodePopupWindow(QtWidgets.QDialog):
    def __init__(self, qr_path=None, file_path=None, operation_type="加密", parent=None):
        super().__init__(parent)
        
        # 设置窗口属性
        self.setWindowTitle("二维码")
        self.setWindowFlags(self.windowFlags() | Qt.WindowStaysOnTopHint)  # 窗口保持在最前
        
        # 创建布局
        layout = QtWidgets.QVBoxLayout(self)
        
        # 添加文件信息标签
        self.file_info_label = QtWidgets.QLabel()
        self.file_info_label.setAlignment(Qt.AlignCenter)
        self.file_info_label.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #333333;
                font-weight: bold;
                padding: 5px;
                background-color: #f0f0f0;
                border-radius: 5px;
                margin: 5px;
            }
        """)
        
        # 设置文件信息
        if file_path:
            file_name = os.path.basename(file_path)
            self.file_info_label.setText(f"正在{operation_type}: {file_name}")
        else:
            self.file_info_label.setText(f"正在{operation_type}: 未知文件")
        
        layout.addWidget(self.file_info_label)
        
        # 二维码显示标签
        self.qr_label = QtWidgets.QLabel()
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setMinimumSize(200, 200)  # 设置最小尺寸以适应整个框
        
        # 如果传入了二维码路径，显示二维码
        if qr_path and os.path.exists(qr_path):
            self.set_qr_code(qr_path)
        else:
            self.qr_label.setText("等待生成二维码...")
            
        # 添加二维码标签到布局
        layout.addWidget(self.qr_label)
        
        # 添加进度条
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximumWidth(300)  # 限制进度条宽度
        self.progress_bar.setMinimumHeight(15)  # 设置最小高度
        layout.addWidget(self.progress_bar)
        
        # 添加状态标签
        self.status_label = QtWidgets.QLabel("准备中...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-size: 12px; color: #666666;")
        layout.addWidget(self.status_label)
        
        # 设置初始大小
        self.resize(250, 380)  # 增加高度以适应文件信息标签
        
    def set_qr_code(self, qr_path):
        """设置二维码图像"""
        try:
            qr_pixmap = QtGui.QPixmap(qr_path)
            self.qr_label.setPixmap(qr_pixmap.scaled(
                250, 250,  # 将二维码尺寸改大到250x250
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation
            ))
        except Exception as e:
            print(f"设置二维码图像时出错: {str(e)}")
            self.qr_label.setText("加载二维码失败")
    
    def update_file_info(self, file_path, operation_type="加密"):
        """更新文件信息"""
        try:
            if file_path:
                file_name = os.path.basename(file_path)
                self.file_info_label.setText(f"正在{operation_type}: {file_name}")
            else:
                self.file_info_label.setText(f"正在{operation_type}: 未知文件")
        except Exception as e:
            print(f"更新文件信息出错: {str(e)}")
    
    def update_progress(self, progress):
        """更新进度条"""
        try:
            self.progress_bar.setValue(progress)
        except Exception as e:
            print(f"更新进度条出错: {str(e)}")
    
    def update_status(self, status):
        """更新状态标签"""
        try:
            self.status_label.setText(status)
        except Exception as e:
            print(f"更新状态标签出错: {str(e)}")
    
    def show_at_cursor(self, x, y):
        """在指定坐标显示窗口"""
        try:
            self.move(x, y)
            self.show()
            self.raise_()  # 确保窗口在最前
            self.activateWindow()  # 激活窗口
        except Exception as e:
            print(f"显示二维码弹窗出错: {str(e)}")

# --- 鼠标监控线程类 ---
class MouseMonitorThread(QThread):
    # 定义信号
    file_detected = pyqtSignal(str)  # 检测到有效文件信号
    show_qr_popup = pyqtSignal(str, int, int)  # 显示二维码弹窗信号，传递文件路径和鼠标坐标

    def __init__(self, parent=None):
        super().__init__(parent)
        self.running = True
        self.hover_start_time = 0
        self.current_file = None
        self.hover_threshold = 3.0  # 悬停阈值，单位为秒
        self.qr_popup_shown = False  # 标记是否已显示二维码弹窗

    def run(self):
        # 初始化COM环境 - 必须在线程开始时初始化
        pythoncom.CoInitialize()

        try:
            while self.running:
                try:
                    # 获取当前鼠标位置
                    flags, hcursor, (x, y) = win32gui.GetCursorInfo()

                    # 获取鼠标下方窗口句柄
                    hwnd = win32gui.WindowFromPoint((x, y))

                    # 检查窗口是否为文件资源管理器 - 更严格的检查
                    if self.is_file_explorer(hwnd):
                        print(f"鼠标在文件资源管理器中，坐标 ({x}, {y})")

                        # 获取鼠标所指向的文件路径
                        file_path = self.get_file_under_cursor(hwnd, x, y)

                        # 如果找到了文件路径且与当前记录的不同
                        if file_path and os.path.isfile(file_path):
                            if self.current_file != file_path:
                                # 新文件，重置计时器
                                print(f"检测到新文件: {file_path}, 开始计时")
                                self.current_file = file_path
                                self.hover_start_time = time.time()
                                self.qr_popup_shown = False
                            elif time.time() - self.hover_start_time >= self.hover_threshold and not self.qr_popup_shown:
                                # 在同一文件上悬停超过阈值时间，且尚未显示二维码弹窗
                                print(f"文件悬停时间超过阈值: {file_path}, 触发加密/解密")
                                # 先发送显示二维码弹窗的信号
                                self.show_qr_popup.emit(file_path, x, y)
                                self.qr_popup_shown = True
                                # 然后发送文件检测信号，触发加密/解密
                                self.file_detected.emit(file_path)
                                # 重置计时器，避免重复触发
                                self.hover_start_time = time.time() + 10  # 添加一个冷却期
                            else:
                                # 打印当前悬停时间（调试信息）
                                remaining = self.hover_threshold - (time.time() - self.hover_start_time)
                                if remaining > 0 and remaining % 1 < 0.1:  # 每秒打印一次
                                    print(f"悬停中: {file_path}, 还需 {remaining:.1f} 秒")
                        else:
                            if file_path:
                                print(f"获取到路径，但不是有效文件: {file_path}")
                            # 没有文件或不是有效文件，重置
                            if self.current_file is not None:
                                print(f"文件路径不再有效，重置计时: {self.current_file}")
                                self.current_file = None
                                self.qr_popup_shown = False
                    else:
                        # 不在文件资源管理器中，重置
                        if self.current_file is not None:
                            print("不在文件资源管理器中，重置计时")
                            self.current_file = None
                            self.qr_popup_shown = False

                    # 短暂休眠，避免CPU占用过高
                    time.sleep(0.1)

                except Exception as e:
                    print(f"鼠标监控错误: {str(e)}")
                    time.sleep(1)  # 发生错误时稍微休眠长一点
        finally:
            # 确保在线程退出时释放COM环境
            pythoncom.CoUninitialize()

    def stop(self):
        """停止线程运行"""
        self.running = False
        self.wait()

    def is_file_explorer(self, hwnd):
        """检查窗口是否为文件资源管理器或桌面"""
        try:
            # 获取窗口类名
            class_name = win32gui.GetClassName(hwnd)

            # 获取进程ID
            _, pid = win32process.GetWindowThreadProcessId(hwnd)

            # 获取进程名
            try:
                process = psutil.Process(pid)
                process_name = process.name().lower()

                # 检查是否为文件资源管理器或桌面
                return ('explorer.exe' in process_name or
                        'CabinetWClass' in class_name or
                        'ExploreWClass' in class_name or
                        'Progman' in class_name or  # 桌面窗口类名
                        'WorkerW' in class_name)    # 桌面工作窗口类名
            except:
                return False
        except:
            return False

    def get_file_under_cursor(self, hwnd, x, y):
        """尝试获取鼠标下的文件绝对路径"""
        try:
            # 先获取鼠标所在窗口句柄及对应类名
            cursor_hwnd = win32gui.WindowFromPoint((x, y))
            class_name = win32gui.GetClassName(cursor_hwnd)
            print(f"窗口类名: {class_name}")

            # 检查是否为桌面
            if class_name in ['Progman', 'WorkerW']:
                return self.get_desktop_file_under_cursor(x, y)

            # 方法A：如果是 DirectUIHWND 类型，先尝试 Shell32 方法
            if class_name == 'DirectUIHWND':
                try:
                    import win32com.client
                    shell = win32com.client.Dispatch("Shell.Application")
                    for window in shell.Windows():
                        if window.HWND == hwnd:
                            folder_path = window.Document.Folder.Self.Path
                            print(f"Shell32获取到文件夹路径: {folder_path}")
                            rect = win32gui.GetWindowRect(hwnd)
                            rel_x = x - rect[0]
                            rel_y = y - rect[1]
                            items = window.Document.Items()
                            for i in range(items.Count):
                                item = items.Item(i)
                                item_rect = item.GetRect()  # (left, top, right, bottom)
                                if self.is_point_in_rect((rel_x, rel_y), item_rect):
                                    file_path = item.Path
                                    if os.path.exists(file_path) and os.path.isfile(file_path):
                                        print(f"Shell32方法获取鼠标位置文件绝对路径: {file_path}")
                                        return file_path
                except Exception as e:
                    print(f"Shell32方法错误: {str(e)}")

            # 方法B：对于 SysTreeView32 或 SysListView32 类型，尝试通过窗口标题拼接
            if class_name in ['SysTreeView32', 'SysListView32']:
                try:
                    explorer_path = self.get_explorer_path(hwnd)
                    print(f"探测到的资源管理器路径: {explorer_path}")
                    title = win32gui.GetWindowText(cursor_hwnd)
                    if title and not title.startswith("地址:") and not title.startswith("Address:"):
                        full_path = os.path.join(explorer_path, title) if explorer_path else title
                        if os.path.exists(full_path) and os.path.isfile(full_path):
                            print(f"标题栏方法获取鼠标位置文件绝对路径: {full_path}")
                            return full_path
                except Exception as e:
                    print(f"标题栏解析错误: {str(e)}")

            # 方法C：使用 pywinauto 获取鼠标下控件信息，再进行绝对路径拼接
            try:
                from pywinauto import Desktop
                # 注意：from_point 分别传入 x 和 y 两个参数
                element = Desktop(backend="uia").from_point(x, y)
                if element:
                    element_name = element.element_info.name  # 通常仅返回文件名，如 "数据结构.docx"
                    print(f"pywinauto 获取到元素名称: {element_name}")
                    # 如果获取到的是绝对路径，直接返回
                    if os.path.isabs(element_name) and os.path.exists(element_name) and os.path.isfile(element_name):
                        print(f"pywinauto方法直接获取到绝对路径: {element_name}")
                        return element_name
                    # 否则，尝试获取当前 Explorer 的目录，并拼接成完整绝对路径
                    explorer_path = self.get_explorer_path(hwnd)
                    if explorer_path:
                        candidate = os.path.join(explorer_path, element_name)
                        # 如果拼接后存在该文件，则返回
                        if os.path.exists(candidate) and os.path.isfile(candidate):
                            print(f"pywinauto方法返回绝对路径: {candidate}")
                            return candidate
                else:
                    print("pywinauto未能获取到有效的控件")
            except Exception as e:
                print(f"pywinauto方法错误: {str(e)}")

            return None

        except Exception as e:
            print(f"获取文件路径全局错误: {str(e)}")
            return None

    def get_desktop_file_under_cursor(self, x, y):
        """获取桌面上的文件路径"""
        try:
            # 获取桌面路径
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            if not os.path.exists(desktop_path):
                # 尝试其他可能的桌面路径
                desktop_path = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
            
            if not os.path.exists(desktop_path):
                print("无法找到桌面路径")
                return None
            
            # 使用 pywinauto 获取桌面上的元素
            try:
                from pywinauto import Desktop
                element = Desktop(backend="uia").from_point(x, y)
                if element:
                    element_name = element.element_info.name
                    element_class = element.element_info.class_name
                    print(f"桌面元素名称: {element_name}, 类名: {element_class}")
                    
                    # 过滤掉系统UI元素
                    system_elements = [
                        "NVIDIA GeForce Overlay", "NVIDIA GeForce Experience",
                        "Windows Security", "Windows Defender",
                        "System Tray", "Taskbar", "Start Menu",
                        "Desktop", "Recycle Bin", "This PC",
                        "Network", "Control Panel", "Settings"
                    ]
                    
                    if element_name in system_elements:
                        print(f"跳过系统元素: {element_name}")
                        return None
                    
                    # 检查是否为文件
                    if element_name and not element_name.startswith("地址:") and not element_name.startswith("Address:"):
                        # 尝试拼接桌面路径
                        candidate = os.path.join(desktop_path, element_name)
                        if os.path.exists(candidate) and os.path.isfile(candidate):
                            print(f"桌面文件路径: {candidate}")
                            return candidate
                        
                        # 如果直接是绝对路径
                        if os.path.isabs(element_name) and os.path.exists(element_name) and os.path.isfile(element_name):
                            print(f"桌面绝对路径: {element_name}")
                            return element_name
                        
                        # 尝试获取父元素，可能是桌面图标容器
                        try:
                            parent = element.parent()
                            if parent:
                                parent_name = parent.element_info.name
                                print(f"父元素名称: {parent_name}")
                                
                                # 如果父元素是桌面，尝试直接拼接文件名
                                if "Desktop" in parent_name or "桌面" in parent_name:
                                    candidate = os.path.join(desktop_path, element_name)
                                    if os.path.exists(candidate) and os.path.isfile(candidate):
                                        print(f"通过父元素检测到桌面文件: {candidate}")
                                        return candidate
                        except Exception as e:
                            print(f"获取父元素失败: {str(e)}")
                            
            except Exception as e:
                print(f"桌面文件检测错误: {str(e)}")
            
            # 备用方法：直接扫描桌面文件
            return self.scan_desktop_files(x, y, desktop_path)
            
        except Exception as e:
            print(f"获取桌面文件路径错误: {str(e)}")
            return None

    def scan_desktop_files(self, x, y, desktop_path):
        """扫描桌面文件，通过坐标匹配"""
        try:
            # 获取桌面窗口句柄
            desktop_hwnd = win32gui.FindWindow("Progman", None)
            if not desktop_hwnd:
                desktop_hwnd = win32gui.FindWindow("WorkerW", None)
            
            if not desktop_hwnd:
                print("无法找到桌面窗口")
                return None
            
            # 获取桌面窗口矩形
            desktop_rect = win32gui.GetWindowRect(desktop_hwnd)
            print(f"桌面窗口矩形: {desktop_rect}")
            
            # 获取桌面上的所有文件
            desktop_files = []
            try:
                for item in os.listdir(desktop_path):
                    item_path = os.path.join(desktop_path, item)
                    if os.path.isfile(item_path):
                        desktop_files.append(item_path)
            except Exception as e:
                print(f"扫描桌面文件失败: {str(e)}")
                return None
            
            print(f"桌面文件列表: {desktop_files}")
            
            # 使用Shell32获取文件位置信息
            try:
                import win32com.client
                shell = win32com.client.Dispatch("Shell.Application")
                desktop_folder = shell.NameSpace(desktop_path)
                
                for file_path in desktop_files:
                    try:
                        file_name = os.path.basename(file_path)
                        file_item = desktop_folder.ParseName(file_name)
                        if file_item:
                            # 获取文件在桌面上的位置
                            file_rect = file_item.GetRect()
                            if file_rect:
                                # 检查鼠标是否在文件区域内
                                if self.is_point_in_rect((x, y), file_rect):
                                    print(f"通过坐标匹配找到桌面文件: {file_path}")
                                    return file_path
                    except Exception as e:
                        print(f"检查文件位置失败: {str(e)}")
                        continue
                        
            except Exception as e:
                print(f"Shell32获取文件位置失败: {str(e)}")
            
            return None
            
        except Exception as e:
            print(f"扫描桌面文件错误: {str(e)}")
            return None

    def is_point_in_rect(self, point, rect):
        """检查点是否在矩形区域内"""
        try:
            x, y = point
            left, top, right, bottom = rect
            return left <= x <= right and top <= y <= bottom
        except:
            return False

    def get_explorer_path(self, hwnd):
        """使用多种方法尝试获取当前资源管理器窗口的目录绝对路径"""
        # 方法1：通过 Shell.Application 获取
        try:
            import win32com.client
            shell = win32com.client.Dispatch("Shell.Application")
            for window in shell.Windows():
                # 由于 hwnd 可能和 window.HWND 不完全一致，采用"接近匹配"策略
                if abs(window.HWND - hwnd) < 100:
                    folder_path = window.Document.Folder.Self.Path
                    if os.path.isdir(folder_path):
                        print(f"Shell方法获取到文件夹路径: {folder_path}")
                        return folder_path
            # 如果没有精确匹配，可以尝试返回第一个非空的路径
            for window in shell.Windows():
                folder_path = window.Document.Folder.Self.Path
                if os.path.isdir(folder_path):
                    print(f"Shell方法（备选）获取到文件夹路径: {folder_path}")
                    return folder_path
        except Exception as e:
            print(f"Shell方法获取资源管理器路径错误: {str(e)}")

        # 方法2：利用当前选中的项目作为备选（例如在 Explorer 中当前选中项的路径）
        try:
            import win32com.client
            shell = win32com.client.Dispatch("Shell.Application")
            for window in shell.Windows():
                selected = window.Document.SelectedItems()
                if selected.Count > 0:
                    candidate = selected.Item(0).Path
                    if candidate and os.path.isfile(candidate):
                        folder = os.path.dirname(candidate)
                        print(f"利用选中项获取到文件夹路径: {folder}")
                        return folder
        except Exception as e:
            print(f"利用选中项获取资源管理器路径错误: {str(e)}")

        # 方法3：利用窗口标题解析（有时 Explorer 的标题中会包含目录）
        try:
            title = win32gui.GetWindowText(hwnd)
            if title and " - " in title:
                candidate = title.split(" - ")[0]
                if os.path.isdir(candidate):
                    print(f"窗口标题方法解析到路径: {candidate}")
                    return candidate
        except Exception as e:
            print(f"窗口标题解析获取资源管理器路径错误: {str(e)}")

        return None


# --- 修改 MainWindow 类 ---
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("文件自动加密系统")
        self.resize(800, 600)

        # 创建菜单栏
        self.menu_bar = QtWidgets.QMenuBar(self)
        self.file_menu = self.menu_bar.addMenu("文件")
        self.settings_action = self.file_menu.addAction("设置")
        self.settings_action.triggered.connect(self.show_settings)

        # 添加密钥管理菜单
        self.key_menu = self.menu_bar.addMenu("密钥管理")
        self.save_key_action = self.key_menu.addAction("保存RSA密钥")
        self.save_key_action.triggered.connect(self.save_rsa_key)
        self.load_key_action = self.key_menu.addAction("加载RSA密钥")
        self.load_key_action.triggered.connect(self.load_rsa_key)

        self.setMenuBar(self.menu_bar)

        # 主内容widget
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        main_layout = QtWidgets.QVBoxLayout(central_widget)
        # 不再用main_layout.setMenuBar(self.menu_bar)

        # 内容布局
        content_layout = QtWidgets.QHBoxLayout()
        main_layout.addLayout(content_layout)
        
        # 左侧面板
        left_panel = QtWidgets.QVBoxLayout()
        
        # 状态面板
        status_group = QtWidgets.QGroupBox("系统状态")
        status_layout = QtWidgets.QVBoxLayout()
        
        # 显示当前状态
        self.status_label = QtWidgets.QLabel("系统已启动，正在监控文件...")
        self.status_label.setAlignment(QtCore.Qt.AlignCenter)
        status_layout.addWidget(self.status_label)
        
        # 密码输入框
        password_layout = QtWidgets.QHBoxLayout()
        password_layout.addWidget(QtWidgets.QLabel("密码:"))
        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_edit.setPlaceholderText("输入密码（可选）")
        password_layout.addWidget(self.password_edit)
        status_layout.addLayout(password_layout)
        
        # 当前监控文件显示
        self.current_file_label = QtWidgets.QLabel("未检测到文件")
        self.current_file_label.setWordWrap(True)
        self.current_file_label.setAlignment(QtCore.Qt.AlignCenter)
        status_layout.addWidget(self.current_file_label)
        
        # 添加开关按钮
        self.toggle_button = QtWidgets.QPushButton("停止监控")
        self.toggle_button.setMinimumHeight(40)
        self.toggle_button.clicked.connect(self.toggle_monitoring)
        
        # 设置按钮样式
        self.toggle_button.setStyleSheet("""
            QPushButton {
                background-color: rgba(79, 195, 247, 180);
                color: black;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgba(41, 182, 246, 180);
            }
            QPushButton:pressed {
                background-color: rgba(3, 155, 229, 180);
            }
        """)
        
        status_layout.addWidget(self.toggle_button)
        status_group.setLayout(status_layout)
        left_panel.addWidget(status_group)
        
        # 进度显示
        progress_group = QtWidgets.QGroupBox("加密进度")
        progress_layout = QtWidgets.QVBoxLayout()
        
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        
        self.progress_label = QtWidgets.QLabel("就绪")
        self.progress_label.setAlignment(QtCore.Qt.AlignCenter)
        progress_layout.addWidget(self.progress_label)
        
        progress_group.setLayout(progress_layout)
        left_panel.addWidget(progress_group)
        
        # 右侧面板 - 二维码显示
        right_panel = QtWidgets.QVBoxLayout()
        
        qr_group = QtWidgets.QGroupBox("二维码")
        qr_layout = QtWidgets.QVBoxLayout()
        
        self.qr_label = QtWidgets.QLabel()
        self.qr_label.setAlignment(QtCore.Qt.AlignCenter)
        self.qr_label.setMinimumSize(300, 300)
        self.qr_label.setText("等待生成二维码...")
        qr_layout.addWidget(self.qr_label)
        
        qr_group.setLayout(qr_layout)
        right_panel.addWidget(qr_group)
        
        # 添加左右面板到内容布局
        content_layout.addLayout(left_panel, 1)
        content_layout.addLayout(right_panel, 1)
        
        # 添加日志区域
        log_group = QtWidgets.QGroupBox("操作日志")
        log_layout = QtWidgets.QHBoxLayout()  
        
        # 日志文本区域
        log_text_layout = QtWidgets.QVBoxLayout()
        self.log_text = QtWidgets.QTextEdit()
        self.log_text.setReadOnly(True)
        log_text_layout.addWidget(self.log_text)
        
        # 服务器连接状态指示器
        status_indicator_layout = QtWidgets.QVBoxLayout()
        status_indicator_layout.addStretch()  # 添加弹性空间，让指示器居中
        
        # 创建状态指示器标签
        self.status_indicator = QtWidgets.QLabel()
        self.status_indicator.setFixedSize(20, 20)  # 设置固定大小
        self.status_indicator.setStyleSheet("""
            QLabel {
                background-color: #cccccc;  /* 默认灰色 */
                border-radius: 10px;  /* 圆形 */
                border: 2px solid #999999;
            }
        """)
        self.status_indicator.setAlignment(QtCore.Qt.AlignCenter)
        
        # 添加状态文字
        self.status_text = QtWidgets.QLabel("服务器状态")
        self.status_text.setAlignment(QtCore.Qt.AlignCenter)
        self.status_text.setStyleSheet("font-size: 10px; color: #666666;")
        
        status_indicator_layout.addWidget(self.status_indicator, 0, QtCore.Qt.AlignCenter)
        status_indicator_layout.addWidget(self.status_text, 0, QtCore.Qt.AlignCenter)
        status_indicator_layout.addStretch()  # 添加弹性空间
        
        # 将日志文本和状态指示器添加到水平布局
        log_layout.addLayout(log_text_layout, 1)  # 日志文本占主要空间
        log_layout.addLayout(status_indicator_layout, 0)  # 状态指示器占较小空间
        
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)
        
        # 初始化属性
        self.monitoring_active = True
        self.mouse_monitor = None
        self.encrypted_files = set()  # 用于记录已加密的文件
        self.acceleration_method = None
        self.thread_count = multiprocessing.cpu_count()
        self.encryption_thread = None
        self.decryption_thread = None  # 添加解密线程属性
        self.rsa_private_key = None
        self.rsa_key = None  # 添加rsa_key属性初始化
        self.decrypted_files = set()  # 用于记录已解密的文件
        self.qr_popup = None  # 二维码弹窗
        self.server_connected = False  # 服务器连接状态
        self.session_id = load_session_id()
        if not self.session_id:
            self.register_session()
        
        # 初始化WebSocket管理器
        if HAS_WEBSOCKET:
            self.ws_manager = WebSocketManager()
            self.ws_manager.connected.connect(self.on_websocket_connected)
            self.ws_manager.disconnected.connect(self.on_websocket_disconnected)
            self.ws_manager.error_occurred.connect(self.on_websocket_error)
            
            # 注册消息处理器
            self.ws_manager.register_handler("encryption_approved", self.on_encryption_approved)
            self.ws_manager.register_handler("encryption_rejected", self.on_encryption_rejected)
        else:
            self.ws_manager = None
        
        # 启动鼠标监控线程
        self.start_mouse_monitoring()
        
        # 添加日志
        self.add_log("系统已启动，开始监控文件...")
        
        # 自动连接服务器
        self.connect_to_server()
    
    def connect_to_server(self):
        """连接到服务器"""
        if HAS_WEBSOCKET and self.ws_manager:
            # 使用WebSocket连接
            self.add_log("正在连接WebSocket服务器...")
            self.ws_manager.start()
        else:
            # 使用HTTP连接（备用方案）
            self.connect_to_server_http()
    
    def connect_to_server_http(self):
        """使用HTTP连接服务器（备用方案）"""
        try:
            import requests
            
            # 尝试连接服务器（使用配置文件中的服务器地址）
            test_url = f"{SERVER_CONFIG['base_url']}{SERVER_CONFIG['endpoints']['health']}"
            
            self.add_log("正在连接HTTP服务器...")
            
            # 设置超时时间为配置文件中的值
            response = requests.get(test_url, timeout=SERVER_CONFIG['timeout'])
            
            if response.status_code == 200:
                self.server_connected = True
                self.add_log("HTTP连接成功")
                self.update_server_status_indicator(True)
            else:
                self.server_connected = False
                self.add_log(f"HTTP连接失败，状态码: {response.status_code}")
                self.update_server_status_indicator(False)
                
        except requests.exceptions.Timeout:
            self.server_connected = False
            self.add_log("HTTP连接超时")
            self.update_server_status_indicator(False)
        except requests.exceptions.ConnectionError:
            self.server_connected = False
            self.add_log("HTTP连接错误：无法连接到服务器")
            self.update_server_status_indicator(False)
        except Exception as e:
            self.server_connected = False
            self.add_log(f"HTTP连接失败：{str(e)}")
            self.update_server_status_indicator(False)
    
    def on_websocket_connected(self):
        """WebSocket连接成功回调"""
        self.server_connected = True
        self.add_log("WebSocket连接成功")
        self.update_server_status_indicator(True)
    
    def on_websocket_disconnected(self):
        """WebSocket连接断开回调"""
        self.server_connected = False
        self.add_log("WebSocket连接断开")
        self.update_server_status_indicator(False)
    
    def on_websocket_error(self, error: str):
        """WebSocket错误回调"""
        self.add_log(f"WebSocket错误: {error}")
        self.update_server_status_indicator(False)
    
    def on_encryption_approved(self, data: dict):
        """加密请求被批准"""
        try:
            session_id = data.get("session_id")
            symmetric_key_hex = data.get("symmetric_key")
            salt_hex = data.get("salt")
            
            if symmetric_key_hex:
                symmetric_key = bytes.fromhex(symmetric_key_hex)
                salt = bytes.fromhex(salt_hex) if salt_hex else None
                
                self.add_log(f"加密请求已批准，会话ID: {session_id}")
                # 这里可以继续加密流程
            else:
                self.add_log("加密请求批准但未收到密钥")
        except Exception as e:
            print(f"处理加密批准时出错: {str(e)}")
            self.add_log(f"处理加密批准时出错: {str(e)}")
    
    def on_encryption_rejected(self, data: dict):
        """加密请求被拒绝"""
        try:
            session_id = data.get("session_id")
            reason = data.get("reason", "未知原因")
            self.add_log(f"加密请求被拒绝，会话ID: {session_id}，原因: {reason}")
        except Exception as e:
            print(f"处理加密拒绝时出错: {str(e)}")
            self.add_log(f"处理加密拒绝时出错: {str(e)}")

    def update_server_status_indicator(self, connected):
        """更新服务器状态指示器"""
        if connected:
            # 绿色表示连接成功
            self.status_indicator.setStyleSheet("""
                QLabel {
                    background-color: #4CAF50;  /* 绿色 */
                    border-radius: 10px;
                    border: 2px solid #45a049;
                }
            """)
            self.status_text.setText("已连接")
            self.status_text.setStyleSheet("font-size: 10px; color: #4CAF50; font-weight: bold;")
        else:
            # 灰色表示连接失败
            self.status_indicator.setStyleSheet("""
                QLabel {
                    background-color: #cccccc;  /* 灰色 */
                    border-radius: 10px;
                    border: 2px solid #999999;
                }
            """)
            self.status_text.setText("未连接")
            self.status_text.setStyleSheet("font-size: 10px; color: #666666;")

    def add_log(self, message):
        """添加日志消息"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
    
    def start_mouse_monitoring(self):
        """启动鼠标监控线程"""
        if not self.mouse_monitor:
            self.mouse_monitor = MouseMonitorThread(self)
            self.mouse_monitor.file_detected.connect(self.on_file_detected)
            self.mouse_monitor.show_qr_popup.connect(self.show_qr_popup)
            self.mouse_monitor.start()
            self.monitoring_active = True
            self.toggle_button.setText("停止监控")
            self.add_log("监控线程已启动")
    
    def stop_mouse_monitoring(self):
        """停止鼠标监控线程"""
        if self.mouse_monitor:
            self.mouse_monitor.stop()
            self.mouse_monitor = None
            self.monitoring_active = False
            self.toggle_button.setText("开始监控")
            self.add_log("监控线程已停止")
    
    def toggle_monitoring(self):
        """切换监控状态"""
        if self.monitoring_active:
            self.stop_mouse_monitoring()
        else:
            self.start_mouse_monitoring()
    
    def on_file_detected(self, file_path):
        """处理检测到的文件"""
        try:
            # 如果文件已经加密过或解密过，则忽略
            if file_path in self.encrypted_files or file_path in self.decrypted_files:
                return
                
            self.current_file_label.setText(f"检测到文件: {file_path}")
            self.add_log(f"检测到文件: {file_path}")
            
            # 判断文件是否为加密文件（.enc后缀）
            if file_path.endswith('.enc'):
                # 自动启动解密
                self.auto_decrypt_file(file_path)
            else:
                # 自动启动加密
                self.auto_encrypt_file(file_path)
        except Exception as e:
            print(f"处理检测到的文件时出错: {str(e)}")
            self.add_log(f"处理文件时出错: {str(e)}")
    
    def auto_encrypt_file(self, file_path):
        """自动加密检测到的文件"""
        try:
            # 更新UI
            self.status_label.setText(f"正在加密文件...")
            self.progress_bar.setValue(0)
            self.progress_label.setText("准备加密...")
            
            # 获取密码
            password = self.password_edit.text()
            
            # 启动加密线程
            self.encryption_thread = EncryptionThread(
                file_path,
                acceleration_method=self.acceleration_method,
                thread_count=self.thread_count,
                password=password,
                session_id=self.session_id  # 传递已保存的session_id
            )
            
            # 连接信号
            self.encryption_thread.encryption_done.connect(self.encryption_completed)
            self.encryption_thread.encryption_failed.connect(self.encryption_failed)
            self.encryption_thread.qr_generated.connect(self.update_qr_display)
            self.encryption_thread.encryption_progress.connect(self.update_progress)
            self.encryption_thread.encryption_status.connect(self.update_status)
            
            # 启动线程
            self.encryption_thread.start()
            
            # 记录此文件已被加密
            self.encrypted_files.add(file_path)
            
            # 添加日志
            self.add_log(f"开始加密文件: {file_path}")
        except Exception as e:
            print(f"启动加密线程时出错: {str(e)}")
            self.add_log(f"启动加密失败: {str(e)}")
            self.status_label.setText(f"启动加密失败: {str(e)}")
    
    def update_progress(self, progress):
        """更新进度条"""
        try:
            self.progress_bar.setValue(progress)
            # 同时更新二维码弹窗的进度条
            if hasattr(self, 'qr_popup') and self.qr_popup:
                self.qr_popup.update_progress(progress)
        except Exception as e:
            print(f"更新进度条时出错: {str(e)}")

    def update_status(self, status):
        """更新状态标签"""
        try:
            self.status_label.setText(status)
            # 同时更新二维码弹窗的状态标签
            if hasattr(self, 'qr_popup') and self.qr_popup:
                self.qr_popup.update_status(status)
        except Exception as e:
            print(f"更新状态标签时出错: {str(e)}")

    def update_qr_display(self, qr_path):
        try:
            qr_pixmap = QtGui.QPixmap(qr_path)
            self.qr_label.setPixmap(qr_pixmap.scaled(
                self.qr_label.width(), self.qr_label.height(),
                QtCore.Qt.KeepAspectRatio,  # 关键：保持原始比例
                QtCore.Qt.SmoothTransformation  # 平滑缩放，减少失真
            ))
        except Exception as e:
            print(f"更新二维码显示时出错: {str(e)}")
            self.qr_label.setText("二维码加载失败")

    def pil2pixmap(self, im):
        """将PIL图像转换为QPixmap用于显示"""
        try:
            im = im.convert("RGB")
            data = im.tobytes("raw", "RGB")
            qimage = QtGui.QImage(data, im.size[0], im.size[1], QtGui.QImage.Format_RGB888)
            pixmap = QtGui.QPixmap.fromImage(qimage)
            return pixmap
        except Exception as e:
            print(f"PIL图像转换出错: {str(e)}")
            return None

    def encryption_completed(self, encrypted_file_path):
        """加密完成的处理"""
        try:
            if encrypted_file_path:  # 加密成功
                print(f"文件已加密，保存为: {encrypted_file_path}")
                
                # 更新状态
                self.status_label.setText(f"加密完成: {encrypted_file_path}")
                self.progress_bar.setValue(100)
                self.progress_label.setText("加密完成")
                
                # 加密成功时自动关闭二维码弹窗
                if hasattr(self, 'qr_popup') and self.qr_popup:
                    self.qr_popup.close()
                    self.qr_popup = None
                
                # 添加日志
                self.add_log(f"文件加密完成: {encrypted_file_path}")
            else:  # 加密失败
                print("文件加密失败")
                
                # 更新状态
                self.status_label.setText("加密失败")
                self.progress_bar.setValue(0)
                self.progress_label.setText("加密失败")
                
                # 加密失败时不关闭二维码弹窗，让用户手动关闭
                # 二维码弹窗会显示失败状态
                
                # 添加日志
                self.add_log("文件加密失败")
            
            # 重置进度条
            self.progress_bar.setValue(0)
            self.progress_label.setText("就绪")
        except Exception as e:
            print(f"处理加密完成时出错: {str(e)}")
            self.add_log(f"处理加密完成时出错: {str(e)}")

    def encryption_failed(self, error):
        """加密失败的回调"""
        try:
            print(f"加密失败: {error}")
            
            # 更新状态
            self.status_label.setText(f"加密失败: {error}")
            self.progress_bar.setValue(0)
            self.progress_label.setText("加密失败")
            
            # 加密失败时不关闭二维码弹窗，让用户手动关闭
            # 二维码弹窗会显示失败状态
            
            # 添加日志
            self.add_log(f"文件加密失败: {error}")
            
            # 重置进度条
            self.progress_bar.setValue(0)
            self.progress_label.setText("就绪")
        except Exception as e:
            print(f"处理加密失败时出错: {str(e)}")
            self.add_log(f"处理加密失败时出错: {str(e)}")

    def auto_decrypt_file(self, file_path):
        """自动解密检测到的加密文件"""
        try:
            # 更新UI
            self.status_label.setText(f"正在解密文件...")
            self.progress_bar.setValue(0)
            self.progress_label.setText("准备解密...")
            
            # 如果尚未加载RSA密钥，提示用户加载
            if not hasattr(self, 'rsa_key') or self.rsa_key is None:
                # 提示用户先加载密钥
                reply = QtWidgets.QMessageBox.question(
                    self, 
                    "需要RSA密钥", 
                    "解密需要RSA私钥。是否立即加载RSA密钥？",
                    QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
                )
                
                if reply == QtWidgets.QMessageBox.Yes:
                    self.load_rsa_key()
                else:
                    self.add_log("解密已取消：未加载RSA密钥")
                    return
                
                # 如果用户取消加载或加载失败，则退出
                if not hasattr(self, 'rsa_key') or self.rsa_key is None:
                    self.add_log("解密已取消：未加载RSA密钥")
                    return
            
            # 启动解密线程
            self.decryption_thread = DecryptionThread(
                file_path,
                rsa_private_key=self.rsa_key
            )
            
            # 连接信号
            self.decryption_thread.decryption_done.connect(self.decryption_completed)
            self.decryption_thread.decryption_failed.connect(self.decryption_failed)
            self.decryption_thread.decryption_progress.connect(self.update_progress)
            self.decryption_thread.decryption_status.connect(self.update_status)
            
            # 启动线程
            self.decryption_thread.start()
            
            # 记录此文件已被解密
            self.decrypted_files.add(file_path)
            
            # 添加日志
            self.add_log(f"开始解密文件: {file_path}")
        except Exception as e:
            print(f"启动解密线程时出错: {str(e)}")
            self.add_log(f"启动解密失败: {str(e)}")
            self.status_label.setText(f"启动解密失败: {str(e)}")

    def decryption_completed(self, decrypted_file_path):
        """解密完成的处理"""
        try:
            if decrypted_file_path:  # 解密成功
                print(f"文件已解密，保存为: {decrypted_file_path}")
                
                # 更新状态
                self.status_label.setText(f"解密完成: {decrypted_file_path}")
                self.progress_bar.setValue(100)
                self.progress_label.setText("解密完成")
                
                # 解密成功时自动关闭二维码弹窗
                if hasattr(self, 'qr_popup') and self.qr_popup:
                    self.qr_popup.close()
                    self.qr_popup = None
                
                # 添加日志
                self.add_log(f"文件解密完成: {decrypted_file_path}")
            else:  # 解密失败
                print("文件解密失败")
                
                # 更新状态
                self.status_label.setText("解密失败")
                self.progress_bar.setValue(0)
                self.progress_label.setText("解密失败")
                
                # 解密失败时不关闭二维码弹窗，让用户手动关闭
                # 二维码弹窗会显示失败状态
                
                # 添加日志
                self.add_log("文件解密失败")
            
            # 重置进度条
            self.progress_bar.setValue(0)
            self.progress_label.setText("就绪")
        except Exception as e:
            print(f"处理解密完成时出错: {str(e)}")
            self.add_log(f"处理解密完成时出错: {str(e)}")

    def decryption_failed(self, error):
        """解密失败的回调"""
        try:
            print(f"解密失败: {error}")
            
            # 更新状态
            self.status_label.setText(f"解密失败: {error}")
            self.progress_bar.setValue(0)
            self.progress_label.setText("解密失败")
            
            # 解密失败时不关闭二维码弹窗，让用户手动关闭
            # 二维码弹窗会显示失败状态
            
            # 添加日志
            self.add_log(f"文件解密失败: {error}")
            
            # 重置进度条
            self.progress_bar.setValue(0)
            self.progress_label.setText("就绪")
        except Exception as e:
            print(f"处理解密失败时出错: {str(e)}")
            self.add_log(f"处理解密失败时出错: {str(e)}")

    def show_settings(self):
        try:
            dialog = SettingsDialog(self)
            if dialog.exec_() == QtWidgets.QDialog.Accepted:
                self.selected_acceleration = dialog.get_selected_acceleration()
                self.thread_count = dialog.get_thread_count()
                self.status_label.setText(f"设置已更新: {self.selected_acceleration}, {self.thread_count}线程")
        except Exception as e:
            import traceback
            traceback.print_exc()
            QtWidgets.QMessageBox.critical(self, "设置弹窗出错", f"设置弹窗出错:\n{e}")

    def save_rsa_key(self):
        """保存RSA密钥对到文件"""
        try:
            if not self.rsa_key:
                QtWidgets.QMessageBox.warning(self, "错误", "没有可用的RSA密钥对")
                return
                
            # 选择保存路径
            file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "保存RSA密钥", "", "密钥文件 (*.pem)"
            )
            
            if file_path:
                try:
                    # 导出私钥
                    private_key_pem = self.rsa_key.export_key()
                    
                    # 写入文件
                    with open(file_path, 'wb') as f:
                        f.write(private_key_pem)
                    
                    QtWidgets.QMessageBox.information(
                        self, 
                        "保存成功", 
                        f"RSA密钥已保存到:\n{file_path}\n\n请妥善保管此文件，它可用于解密您的文件。"
                    )
                except Exception as e:
                    QtWidgets.QMessageBox.critical(
                        self, 
                        "保存失败", 
                        f"保存RSA密钥时出错:\n{str(e)}"
                    )
        except Exception as e:
            print(f"保存RSA密钥时出错: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "错误", f"保存RSA密钥时出错:\n{str(e)}")
    
    def load_rsa_key(self):
        """从文件加载RSA密钥对"""
        try:
            # 选择密钥文件
            file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "加载RSA密钥", "", "密钥文件 (*.pem)"
            )
            
            if file_path:
                try:
                    # 读取密钥文件
                    with open(file_path, 'rb') as f:
                        key_data = f.read()
                    
                    # 导入密钥
                    from Crypto.PublicKey import RSA
                    self.rsa_key = RSA.import_key(key_data)
                    self.rsa_public_key = self.rsa_key.publickey()
                    
                    QtWidgets.QMessageBox.information(
                        self, 
                        "加载成功", 
                        "RSA密钥已成功加载，现在您可以解密使用此密钥加密的文件。"
                    )
                    
                    # 如果当前选择的是加密文件，启用解密按钮
                    if hasattr(self, 'current_file_path') and self.current_file_path and self.current_file_path.endswith('.enc'):
                        if hasattr(self, 'decrypt_button'):
                            self.decrypt_button.setEnabled(True)
                        
                except Exception as e:
                    QtWidgets.QMessageBox.critical(
                        self, 
                        "加载失败", 
                        f"加载RSA密钥时出错:\n{str(e)}"
                    )
        except Exception as e:
            print(f"加载RSA密钥时出错: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "错误", f"加载RSA密钥时出错:\n{str(e)}")

    def show_qr_popup(self, file_path, x, y):
        """显示二维码弹窗"""
        try:
            # 根据文件扩展名判断操作类型
            if file_path.endswith('.enc'):
                operation_type = "解密"
            else:
                operation_type = "加密"
            
            # 检查是否有已保存的session_id
            if hasattr(self, 'session_id') and self.session_id:
                # 使用已保存的session_id生成二维码
                qr_path = main.generate_qr_code(file_path, self.session_id)
                self.add_log(f"使用已保存的session_id生成二维码: {self.session_id}")
            else:
                # 如果没有session_id，使用原来的方法生成二维码
                qr_path = main.generate_qr_code(file_path, "unknown-session")
                self.add_log("未找到session_id，使用默认二维码生成方法")
            
            # 创建二维码弹窗并显示
            self.qr_popup = QRCodePopupWindow(qr_path, file_path, operation_type, self)
            self.qr_popup.show_at_cursor(x, y)
            
            # 添加日志
            self.add_log(f"显示文件二维码: {file_path} ({operation_type})")
        except Exception as e:
            print(f"显示二维码弹窗失败: {str(e)}")
            self.add_log(f"显示二维码弹窗失败: {str(e)}")
            # 尝试显示错误信息
            try:
                QtWidgets.QMessageBox.critical(self, "错误", f"显示二维码弹窗失败:\n{str(e)}")
            except:
                pass

    def register_session(self):
        """注册新会话"""
        try:
            import requests
            url = f"{SERVER_CONFIG['base_url']}{SERVER_CONFIG['endpoints']['register_session']}"
            response = requests.post(url, timeout=SERVER_CONFIG['timeout'])
            if response.status_code == 200:
                data = response.json()
                session_id = data.get("session_id")
                if session_id:
                    save_session_id(session_id)
                    self.session_id = session_id
                    self.add_log(f"已注册新会话: {session_id}")
                else:
                    self.add_log("服务器未返回session_id")
            else:
                self.add_log(f"注册会话失败，状态码: {response.status_code}")
        except Exception as e:
            print(f"注册会话时出错: {e}")
            self.add_log(f"注册会话时出错: {e}")

    def closeEvent(self, event):
        """重写关闭事件，防止主界面被意外关闭"""
        try:
            # 阻止关闭事件
            event.ignore()
            
            # 显示提示信息
            QtWidgets.QMessageBox.information(
                self,
                "提示",
                "主界面不会关闭，程序会继续在后台运行。\n如需完全退出程序，请使用任务管理器。"
            )
            
            # 记录日志
            self.add_log("用户尝试关闭主界面，已阻止")
        except Exception as e:
            print(f"处理关闭事件时出错: {str(e)}")

    def on_encryption_approved(self, data: dict):
        """加密请求被批准"""
        try:
            session_id = data.get("session_id")
            symmetric_key_hex = data.get("symmetric_key")
            salt_hex = data.get("salt")
            
            if symmetric_key_hex:
                symmetric_key = bytes.fromhex(symmetric_key_hex)
                salt = bytes.fromhex(salt_hex) if salt_hex else None
                
                self.add_log(f"加密请求已批准，会话ID: {session_id}")
                # 这里可以继续加密流程
            else:
                self.add_log("加密请求批准但未收到密钥")
        except Exception as e:
            print(f"处理加密批准时出错: {str(e)}")
            self.add_log(f"处理加密批准时出错: {str(e)}")
    
    def on_encryption_rejected(self, data: dict):
        """加密请求被拒绝"""
        try:
            session_id = data.get("session_id")
            reason = data.get("reason", "未知原因")
            self.add_log(f"加密请求被拒绝，会话ID: {session_id}，原因: {reason}")
        except Exception as e:
            print(f"处理加密拒绝时出错: {str(e)}")
            self.add_log(f"处理加密拒绝时出错: {str(e)}") 