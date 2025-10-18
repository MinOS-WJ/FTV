import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import numpy as np
import cv2
import os
import threading
import time
from PIL import Image, ImageTk
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
from tkinter import font

class FileToVideoConverter:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 文件转视频编码器/解码器")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        self.root.minsize(1000, 600)  # 设置最小窗口大小
        
        # 设置主题颜色
        self.setup_theme()
        
        # 创建主容器
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 创建标题
        self.create_header()
        
        # 创建选项卡
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        # 编码页面
        self.encode_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encode_frame, text="📹 编码")
        
        # 解码页面
        self.decode_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decode_frame, text="📁 解码")
        
        # 设置页面
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="⚙️ 设置")
        
        # 声明页面
        self.disclaimer_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.disclaimer_frame, text="📋 声明")
        
        self.create_encode_ui()
        self.create_decode_ui()
        self.create_settings_ui()
        self.create_disclaimer_ui()
        
        # 状态变量
        self.encoding = False
        self.decoding = False
        
        self.encode_start_time = 0
        self.encode_processed_bytes = 0
        self.decode_start_time = 0
        self.decode_processed_bytes = 0
        
        # 配置样式
        self.configure_styles()
        
        # 主题设置
        self.current_theme = self.load_theme()
        self.apply_theme(self.current_theme)
        
        # 加载用户设置
        self.load_settings()

    def setup_theme(self):
        """设置应用主题"""
        # 预设主题
        self.preset_themes = {
            'default': {
                'name': '默认主题',
                'bg_color': '#FFFFFF',
                'fg_color': '#000000',
                'primary': '#2E86AB',
                'secondary': '#A23B72',
                'success': '#28A745',
                'warning': '#FFC107',
                'danger': '#DC3545',
                'light': '#F8F9FA',
                'dark': '#343A40',
                'border': '#DEE2E6'
            },
            'dark': {
                'name': '深色主题',
                'bg_color': '#2B2B2B',
                'fg_color': '#FFFFFF',
                'primary': '#4A9EFF',
                'secondary': '#FF6B9D',
                'success': '#4CAF50',
                'warning': '#FFC107',
                'danger': '#F44336',
                'light': '#3C3C3C',
                'dark': '#FFFFFF',
                'border': '#555555'
            },
            'blue': {
                'name': '蓝色主题',
                'bg_color': '#E3F2FD',
                'fg_color': '#1565C0',
                'primary': '#1976D2',
                'secondary': '#7B1FA2',
                'success': '#388E3C',
                'warning': '#F57C00',
                'danger': '#D32F2F',
                'light': '#F5F5F5',
                'dark': '#0D47A1',
                'border': '#BBDEFB'
            },
            'green': {
                'name': '绿色主题',
                'bg_color': '#E8F5E8',
                'fg_color': '#2E7D32',
                'primary': '#4CAF50',
                'secondary': '#9C27B0',
                'success': '#66BB6A',
                'warning': '#FF9800',
                'danger': '#F44336',
                'light': '#F1F8E9',
                'dark': '#1B5E20',
                'border': '#C8E6C9'
            },
            'purple': {
                'name': '紫色主题',
                'bg_color': '#F3E5F5',
                'fg_color': '#7B1FA2',
                'primary': '#9C27B0',
                'secondary': '#E91E63',
                'success': '#4CAF50',
                'warning': '#FF9800',
                'danger': '#F44336',
                'light': '#FCE4EC',
                'dark': '#4A148C',
                'border': '#E1BEE7'
            }
        }
        
        # 当前主题
        self.current_theme = self.preset_themes['default']

    def apply_theme(self, theme):
        """应用主题"""
        self.current_theme = theme
        self.root.configure(bg=theme['bg_color'])
        self.main_frame.configure(style='Main.TFrame')
        
        # 配置样式
        style = ttk.Style()
        style.configure('Main.TFrame', background=theme['bg_color'])
        style.configure('TLabel', background=theme['bg_color'], foreground=theme['fg_color'])
        
        # 使用系统默认按钮样式，确保文字清晰
        style.configure('TButton')
        style.configure('Primary.TButton')
        style.configure('Success.TButton')
        
        # 更新进度条样式
        style.configure('Custom.Horizontal.TProgressbar',
                       thickness=20,
                       troughcolor=theme['light'],
                       background=theme['success'])
        
        # 更新已存在的组件颜色
        self.update_component_colors(theme)

    def update_component_colors(self, theme):
        """更新已存在组件的颜色"""
        try:
            # 更新文件信息标签
            if hasattr(self, 'file_info_label'):
                self.file_info_label.configure(foreground=theme['primary'])
            
            # 更新速度标签
            if hasattr(self, 'encode_speed_label'):
                self.encode_speed_label.configure(foreground=theme['success'])
            if hasattr(self, 'decode_speed_label'):
                self.decode_speed_label.configure(foreground=theme['success'])
            
            # 更新预览标签
            if hasattr(self, 'preview_label'):
                self.preview_label.configure(foreground=theme['fg_color'])
            if hasattr(self, 'decode_preview_label'):
                self.decode_preview_label.configure(foreground=theme['fg_color'])
            
            # 更新预览信息标签
            if hasattr(self, 'preview_info_label'):
                self.preview_info_label.configure(foreground=theme['primary'])
            if hasattr(self, 'decode_preview_info_label'):
                self.decode_preview_info_label.configure(foreground=theme['primary'])
            
            # 更新声明文本框
            if hasattr(self, 'disclaimer_text'):
                self.disclaimer_text.configure(
                    bg=theme['bg_color'], 
                    fg=theme['fg_color']
                )
            
            # 更新Canvas背景
            if hasattr(self, 'canvas'):
                self.canvas.configure(bg=theme['bg_color'])
                
        except Exception as e:
            print(f"更新组件颜色时出错: {e}")

    def load_theme(self):
        """加载保存的主题"""
        try:
            import json
            with open('theme.json', 'r', encoding='utf-8') as f:
                theme_data = json.load(f)
                return theme_data
        except:
            return self.preset_themes['default']

    def save_theme(self, theme):
        """保存主题"""
        try:
            import json
            with open('theme.json', 'w', encoding='utf-8') as f:
                json.dump(theme, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存主题失败: {e}")

    def create_header(self):
        """创建应用标题"""
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        title_label = ttk.Label(
            header_frame, 
            text="🔐 文件转视频编码器/解码器", 
            font=('Microsoft YaHei UI', 16, 'bold')
        )
        title_label.pack()
        
        subtitle_label = ttk.Label(
            header_frame, 
            text="支持文件加密存储为视频格式，安全可靠", 
            font=('Microsoft YaHei UI', 10)
        )
        subtitle_label.pack(pady=(5, 0))

    def configure_styles(self):
        """配置TTK样式"""
        style = ttk.Style()
        
        # 配置按钮样式
        style.configure('Primary.TButton', 
                       font=('Microsoft YaHei UI', 10, 'bold'),
                       padding=(10, 5))
        
        style.configure('Success.TButton',
                       font=('Microsoft YaHei UI', 10, 'bold'),
                       padding=(10, 5))

    def create_encode_ui(self):
        # 创建主容器 - 左右分栏布局
        main_container = ttk.Frame(self.encode_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 左侧内容区域
        left_frame = ttk.Frame(main_container)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # 右侧预览区域
        right_frame = ttk.LabelFrame(main_container, text="👁️ 预览", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        right_frame.configure(width=300)  # 固定侧边栏宽度
        
        # 文件选择区域
        file_section = ttk.LabelFrame(left_frame, text="📁 文件选择", padding=10)
        file_section.pack(fill=tk.X, pady=(0, 10))
        
        # 输入文件
        input_frame = ttk.Frame(file_section)
        input_frame.pack(fill=tk.X, pady=(0, 8))
        
        ttk.Label(input_frame, text="📄 输入文件:", font=('Microsoft YaHei UI', 10, 'bold')).pack(anchor=tk.W)
        input_entry_frame = ttk.Frame(input_frame)
        input_entry_frame.pack(fill=tk.X, pady=(3, 0))
        
        self.encode_input_entry = ttk.Entry(input_entry_frame, font=('Microsoft YaHei UI', 9))
        self.encode_input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(input_entry_frame, text="📂 浏览", command=self.browse_encode_input).pack(side=tk.RIGHT)
        
        # 输出文件
        output_frame = ttk.Frame(file_section)
        output_frame.pack(fill=tk.X)
        
        ttk.Label(output_frame, text="🎬 输出视频:", font=('Microsoft YaHei UI', 10, 'bold')).pack(anchor=tk.W)
        output_entry_frame = ttk.Frame(output_frame)
        output_entry_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.encode_output_entry = ttk.Entry(output_entry_frame, font=('Microsoft YaHei UI', 9))
        self.encode_output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(output_entry_frame, text="📂 浏览", command=self.browse_encode_output).pack(side=tk.RIGHT)
        
        # 设置区域
        settings_section = ttk.LabelFrame(main_container, text="⚙️ 编码设置", padding=10)
        settings_section.pack(fill=tk.X, pady=(0, 10))
        
        settings_grid = ttk.Frame(settings_section)
        settings_grid.pack(fill=tk.X)
        
        # 密码设置
        ttk.Label(settings_grid, text="🔐 加密密码:", font=('Microsoft YaHei UI', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        password_frame = ttk.Frame(settings_grid)
        password_frame.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=(0, 5))
        
        self.encode_password_entry = ttk.Entry(password_frame, show="*", width=25, font=('Microsoft YaHei UI', 9))
        self.encode_password_entry.pack(side=tk.LEFT)
        
        ttk.Label(password_frame, text="(可选，不填则不加密)", font=('Microsoft YaHei UI', 8)).pack(side=tk.LEFT, padx=(10, 0))
        
        # 帧率设置
        ttk.Label(settings_grid, text="🎞️ 帧率:", font=('Microsoft YaHei UI', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        fps_frame = ttk.Frame(settings_grid)
        fps_frame.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=(0, 5))
        
        self.fps_var = tk.StringVar(value="10")
        fps_entry = ttk.Entry(fps_frame, textvariable=self.fps_var, width=8, font=('Microsoft YaHei UI', 9))
        fps_entry.pack(side=tk.LEFT)
        ttk.Label(fps_frame, text="fps", font=('Microsoft YaHei UI', 9)).pack(side=tk.LEFT, padx=(5, 0))
        
        # 分辨率设置
        ttk.Label(settings_grid, text="📐 图像尺寸:", font=('Microsoft YaHei UI', 10, 'bold')).grid(row=2, column=0, sticky=tk.W)
        resolution_frame = ttk.Frame(settings_grid)
        resolution_frame.grid(row=2, column=1, sticky=tk.W, padx=(10, 0))
        
        self.resolution_var = tk.StringVar(value="256x256")
        resolutions = ["128x128", "256x256", "512x512", "1024x1024", "2048x2048", "4096x4096"]
        self.resolution_combo = ttk.Combobox(
            resolution_frame, 
            textvariable=self.resolution_var, 
            values=resolutions,
            state="readonly",
            width=12,
            font=('Microsoft YaHei UI', 9)
        )
        self.resolution_combo.pack()
        
        # 文件信息显示
        self.file_info_label = ttk.Label(left_frame, text="", font=('Microsoft YaHei UI', 9), 
                                        wraplength=400)
        self.file_info_label.pack(fill=tk.X, pady=(0, 8))
        
        # 进度区域
        progress_section = ttk.LabelFrame(left_frame, text="📊 进度", padding=10)
        progress_section.pack(fill=tk.X, pady=(0, 10))
        
        self.encode_progress = ttk.Progressbar(progress_section, orient=tk.HORIZONTAL, mode='determinate',
                                             style='Custom.Horizontal.TProgressbar')
        self.encode_progress.pack(fill=tk.X, pady=(0, 5))
        
        self.encode_speed_label = ttk.Label(progress_section, text="处理速度: -- MB/s", 
                                           font=('Microsoft YaHei UI', 9))
        self.encode_speed_label.pack()
        
        # 操作按钮
        button_frame = ttk.Frame(left_frame)
        button_frame.pack(fill=tk.X)
        
        self.encode_button = ttk.Button(button_frame, text="🚀 开始编码", command=self.start_encoding)
        self.encode_button.pack(pady=5)
        
        # 配置列权重
        settings_grid.columnconfigure(1, weight=1)
        
        # 右侧预览区域内容
        self.preview_label = ttk.Label(right_frame, text="选择文件后显示预览", 
                                      font=('Microsoft YaHei UI', 10))
        self.preview_label.pack(pady=10)
        
        # 预览信息标签
        self.preview_info_label = ttk.Label(right_frame, text="", 
                                           font=('Microsoft YaHei UI', 9),
                                           wraplength=250)
        self.preview_info_label.pack(pady=(0, 10))

    def create_decode_ui(self):
        # 创建主容器 - 左右分栏布局
        main_container = ttk.Frame(self.decode_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 左侧内容区域
        left_frame = ttk.Frame(main_container)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # 右侧预览区域
        right_frame = ttk.LabelFrame(main_container, text="👁️ 预览", padding=10)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        right_frame.configure(width=300)  # 固定侧边栏宽度
        
        # 文件选择区域
        file_section = ttk.LabelFrame(left_frame, text="📁 文件选择", padding=10)
        file_section.pack(fill=tk.X, pady=(0, 10))
        
        # 输入视频文件
        input_frame = ttk.Frame(file_section)
        input_frame.pack(fill=tk.X, pady=(0, 8))
        
        ttk.Label(input_frame, text="🎬 视频文件:", font=('Microsoft YaHei UI', 10, 'bold')).pack(anchor=tk.W)
        input_entry_frame = ttk.Frame(input_frame)
        input_entry_frame.pack(fill=tk.X, pady=(3, 0))
        
        self.decode_input_entry = ttk.Entry(input_entry_frame, font=('Microsoft YaHei UI', 9))
        self.decode_input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(input_entry_frame, text="📂 浏览", command=self.browse_decode_input).pack(side=tk.RIGHT)
        
        # 输出文件夹
        output_frame = ttk.Frame(file_section)
        output_frame.pack(fill=tk.X)
        
        ttk.Label(output_frame, text="📂 输出文件夹:", font=('Microsoft YaHei UI', 10, 'bold')).pack(anchor=tk.W)
        output_entry_frame = ttk.Frame(output_frame)
        output_entry_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.decode_output_entry = ttk.Entry(output_entry_frame, font=('Microsoft YaHei UI', 9))
        self.decode_output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(output_entry_frame, text="📂 浏览", command=self.browse_decode_output).pack(side=tk.RIGHT)
        
        # 解密设置区域
        decrypt_section = ttk.LabelFrame(left_frame, text="🔓 解密设置", padding=10)
        decrypt_section.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(decrypt_section, text="🔐 解密密码:", font=('Microsoft YaHei UI', 10, 'bold')).pack(anchor=tk.W)
        password_frame = ttk.Frame(decrypt_section)
        password_frame.pack(fill=tk.X, pady=(3, 0))
        
        self.decode_password_entry = ttk.Entry(password_frame, show="*", width=25, font=('Microsoft YaHei UI', 9))
        self.decode_password_entry.pack(side=tk.LEFT)
        
        ttk.Label(password_frame, text="(如果视频已加密，请输入密码)", font=('Microsoft YaHei UI', 8)).pack(side=tk.LEFT, padx=(10, 0))
        
        # 进度区域
        progress_section = ttk.LabelFrame(left_frame, text="📊 进度", padding=10)
        progress_section.pack(fill=tk.X, pady=(0, 10))
        
        self.decode_progress = ttk.Progressbar(progress_section, orient=tk.HORIZONTAL, mode='determinate',
                                             style='Custom.Horizontal.TProgressbar')
        self.decode_progress.pack(fill=tk.X, pady=(0, 5))
        
        self.decode_speed_label = ttk.Label(progress_section, text="处理速度: -- MB/s", 
                                           font=('Microsoft YaHei UI', 9))
        self.decode_speed_label.pack()
        
        # 操作按钮
        button_frame = ttk.Frame(left_frame)
        button_frame.pack(fill=tk.X)
        
        self.decode_button = ttk.Button(button_frame, text="🚀 开始解码", command=self.start_decoding)
        self.decode_button.pack(pady=5)
        
        # 右侧预览区域内容
        self.decode_preview_label = ttk.Label(right_frame, text="选择视频文件后显示预览", 
                                            font=('Microsoft YaHei UI', 10))
        self.decode_preview_label.pack(pady=10)
        
        # 预览信息标签
        self.decode_preview_info_label = ttk.Label(right_frame, text="", 
                                                 font=('Microsoft YaHei UI', 9),
                                                 wraplength=250)
        self.decode_preview_info_label.pack(pady=(0, 10))

    def create_settings_ui(self):
        """创建设置页面 - 改进的布局"""
        # 创建主容器 - 左右分栏布局
        main_container = ttk.Frame(self.settings_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # 左侧设置区域
        left_frame = ttk.Frame(main_container)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # 右侧预览区域
        right_frame = ttk.LabelFrame(main_container, text="👁️ 主题预览", padding=15)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        right_frame.configure(width=350)  # 固定预览区域宽度
        
        # === 左侧设置区域 ===
        
        # 1. 主题设置区域
        theme_section = ttk.LabelFrame(left_frame, text="🎨 主题设置", padding=15)
        theme_section.pack(fill=tk.X, pady=(0, 15))
        
        # 预设主题选择
        ttk.Label(theme_section, text="预设主题:", font=('Microsoft YaHei UI', 10, 'bold')).pack(anchor=tk.W, pady=(0, 8))
        
        theme_frame = ttk.Frame(theme_section)
        theme_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.theme_var = tk.StringVar(value='default')
        theme_names = [(key, theme['name']) for key, theme in self.preset_themes.items()]
        
        # 使用网格布局排列主题选项
        for i, (key, name) in enumerate(theme_names):
            row = i // 2
            col = i % 2
            ttk.Radiobutton(theme_frame, text=name, variable=self.theme_var, value=key,
                           command=self.on_theme_change).grid(row=row, column=col, sticky=tk.W, padx=(0, 20), pady=2)
        
        # 2. 自定义颜色设置区域
        custom_section = ttk.LabelFrame(left_frame, text="🎨 自定义颜色", padding=15)
        custom_section.pack(fill=tk.X, pady=(0, 15))
        
        # 颜色选择器 - 使用网格布局
        color_frame = ttk.Frame(custom_section)
        color_frame.pack(fill=tk.X)
        
        colors_to_set = [
            ('bg_color', '背景颜色', 0, 0),
            ('fg_color', '文字颜色', 0, 1),
            ('primary', '主色调', 1, 0),
            ('secondary', '次要色', 1, 1),
            ('success', '成功色', 2, 0),
            ('warning', '警告色', 2, 1),
            ('danger', '危险色', 3, 0),
            ('light', '浅色', 3, 1),
            ('dark', '深色', 4, 0),
            ('border', '边框色', 4, 1)
        ]
        
        self.color_vars = {}
        for color_key, color_name, row, col in colors_to_set:
            # 标签
            ttk.Label(color_frame, text=f"{color_name}:", font=('Microsoft YaHei UI', 9)).grid(
                row=row*2, column=col*3, sticky=tk.W, padx=(0, 5), pady=2)
            
            # 颜色输入框
            self.color_vars[color_key] = tk.StringVar(value=self.current_theme[color_key])
            color_entry = ttk.Entry(color_frame, textvariable=self.color_vars[color_key], width=12, font=('Microsoft YaHei UI', 8))
            color_entry.grid(row=row*2, column=col*3+1, padx=(0, 5), pady=2)
            
            # 颜色选择按钮
            color_button = ttk.Button(color_frame, text="选择", width=6,
                                     command=lambda k=color_key: self.choose_color(k))
            color_button.grid(row=row*2, column=col*3+2, padx=(0, 10), pady=2)
        
        # 3. 其他设置区域
        other_section = ttk.LabelFrame(left_frame, text="⚙️ 其他设置", padding=15)
        other_section.pack(fill=tk.X, pady=(0, 15))
        
        # 字体设置
        font_frame = ttk.Frame(other_section)
        font_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(font_frame, text="字体大小:", font=('Microsoft YaHei UI', 10, 'bold')).pack(side=tk.LEFT)
        self.font_size_var = tk.StringVar(value="10")
        font_size_combo = ttk.Combobox(font_frame, textvariable=self.font_size_var, 
                                     values=["8", "9", "10", "11", "12", "14", "16"], 
                                     state="readonly", width=8)
        font_size_combo.pack(side=tk.LEFT, padx=(10, 0))
        
        # 窗口设置
        window_frame = ttk.Frame(other_section)
        window_frame.pack(fill=tk.X)
        
        ttk.Label(window_frame, text="窗口设置:", font=('Microsoft YaHei UI', 10, 'bold')).pack(side=tk.LEFT)
        
        self.auto_save_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(window_frame, text="自动保存设置", variable=self.auto_save_var).pack(side=tk.LEFT, padx=(10, 0))
        
        # 4. 操作按钮区域
        button_section = ttk.LabelFrame(left_frame, text="🔧 操作", padding=15)
        button_section.pack(fill=tk.X)
        
        button_frame = ttk.Frame(button_section)
        button_frame.pack(fill=tk.X)
        
        # 按钮布局
        ttk.Button(button_frame, text="💾 保存设置", command=self.save_settings, 
                  style='Success.TButton').pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="🔄 重置默认", command=self.reset_to_default).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="🎨 应用主题", command=self.apply_custom_theme).pack(side=tk.LEFT)
        
        # === 右侧预览区域 ===
        
        # 预览标题
        preview_title = ttk.Label(right_frame, text="当前主题预览", font=('Microsoft YaHei UI', 12, 'bold'))
        preview_title.pack(pady=(0, 15))
        
        # 颜色预览区域
        preview_colors_frame = ttk.LabelFrame(right_frame, text="颜色预览", padding=10)
        preview_colors_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.color_preview_labels = {}
        preview_colors = ['primary', 'secondary', 'success', 'warning', 'danger']
        for i, color_key in enumerate(preview_colors):
            preview_row = ttk.Frame(preview_colors_frame)
            preview_row.pack(fill=tk.X, pady=2)
            
            ttk.Label(preview_row, text=f"{color_key}:", width=10, anchor=tk.W).pack(side=tk.LEFT)
            
            # 使用tk.Label而不是ttk.Label，因为ttk不支持背景色
            color_label = tk.Label(preview_row, text="  ", width=8, relief=tk.RAISED, bd=1)
            color_label.pack(side=tk.LEFT, padx=(5, 10))
            self.color_preview_labels[color_key] = color_label
        
        # 示例文本预览
        preview_text_frame = ttk.LabelFrame(right_frame, text="文本预览", padding=10)
        preview_text_frame.pack(fill=tk.X, pady=(0, 15))
        
        # 普通文本预览
        self.preview_text_label = tk.Label(preview_text_frame, text="普通文本：这是一段示例文本", 
                                          font=('Microsoft YaHei UI', 10), anchor=tk.W)
        self.preview_text_label.pack(fill=tk.X, pady=(0, 5))
        
        # 主色调文本预览
        self.preview_primary_label = tk.Label(preview_text_frame, text="主色调文本：重要信息显示", 
                                             font=('Microsoft YaHei UI', 10, 'bold'), anchor=tk.W)
        self.preview_primary_label.pack(fill=tk.X, pady=(0, 5))
        
        # 成功色文本预览
        self.preview_success_label = tk.Label(preview_text_frame, text="成功色文本：操作成功提示", 
                                             font=('Microsoft YaHei UI', 10), anchor=tk.W)
        self.preview_success_label.pack(fill=tk.X)
        
        # 示例按钮预览
        preview_button_frame = ttk.LabelFrame(right_frame, text="按钮预览", padding=10)
        preview_button_frame.pack(fill=tk.X, pady=(0, 15))
        
        button_preview_frame = ttk.Frame(preview_button_frame)
        button_preview_frame.pack()
        
        # 第一行按钮
        ttk.Button(button_preview_frame, text="主要按钮", style='Primary.TButton').pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_preview_frame, text="成功按钮", style='Success.TButton').pack(side=tk.LEFT)
        
        # 第二行按钮
        button_preview_frame2 = ttk.Frame(preview_button_frame)
        button_preview_frame2.pack(pady=(5, 0))
        
        ttk.Button(button_preview_frame2, text="普通按钮").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_preview_frame2, text="警告按钮").pack(side=tk.LEFT)
        
        # 输入框预览
        preview_input_frame = ttk.LabelFrame(right_frame, text="输入框预览", padding=10)
        preview_input_frame.pack(fill=tk.X)
        
        self.preview_entry = ttk.Entry(preview_input_frame, font=('Microsoft YaHei UI', 10))
        self.preview_entry.pack(fill=tk.X, pady=(0, 5))
        self.preview_entry.insert(0, "输入框示例文本")
        
        self.preview_text_widget = tk.Text(preview_input_frame, height=3, font=('Microsoft YaHei UI', 9))
        self.preview_text_widget.pack(fill=tk.X)
        self.preview_text_widget.insert(tk.END, "多行文本框预览\n支持多行文本输入\n显示文本颜色效果")
        
        # 延迟更新预览，确保所有组件都已创建
        self.root.after(100, self.update_theme_preview)

    def on_theme_change(self):
        """主题改变时的回调"""
        theme_key = self.theme_var.get()
        theme = self.preset_themes[theme_key]
        self.apply_theme(theme)
        self.update_theme_preview()

    def reset_to_default(self):
        """重置为默认主题"""
        self.theme_var.set('default')
        self.on_theme_change()
        messagebox.showinfo("成功", "已重置为默认主题！")

    def choose_color(self, color_key):
        """选择颜色"""
        try:
            from tkinter import colorchooser
            current_color = self.color_vars[color_key].get()
            color = colorchooser.askcolor(initialcolor=current_color, title=f"选择{color_key}颜色")
            if color[1]:  # 如果用户选择了颜色
                self.color_vars[color_key].set(color[1])
                self.update_theme_preview()
        except Exception as e:
            messagebox.showerror("错误", f"颜色选择失败: {str(e)}")

    def update_theme_preview(self):
        """更新主题预览"""
        try:
            # 更新颜色预览标签
            for color_key, label in self.color_preview_labels.items():
                color_value = self.current_theme[color_key]
                label.configure(background=color_value)
            
            # 更新文本预览
            self.preview_text_label.configure(
                foreground=self.current_theme['fg_color'],
                background=self.current_theme['bg_color']
            )
            
            # 更新主色调文本预览
            self.preview_primary_label.configure(
                foreground=self.current_theme['primary'],
                background=self.current_theme['bg_color']
            )
            
            # 更新成功色文本预览
            self.preview_success_label.configure(
                foreground=self.current_theme['success'],
                background=self.current_theme['bg_color']
            )
            
            # 更新输入框预览
            self.preview_entry.configure(
                foreground=self.current_theme['fg_color'],
                background=self.current_theme['light']
            )
            
            # 更新文本框预览
            self.preview_text_widget.configure(
                foreground=self.current_theme['fg_color'],
                background=self.current_theme['light'],
                insertbackground=self.current_theme['fg_color']
            )
            
        except Exception as e:
            print(f"更新预览时出错: {e}")

    def apply_custom_theme(self):
        """应用自定义主题"""
        try:
            # 创建自定义主题
            custom_theme = {}
            for color_key, var in self.color_vars.items():
                custom_theme[color_key] = var.get()
            
            # 验证颜色格式
            for color_key, color_value in custom_theme.items():
                if not color_value.startswith('#') or len(color_value) != 7:
                    raise ValueError(f"颜色 {color_key} 格式不正确")
            
            # 应用主题
            self.apply_theme(custom_theme)
            self.update_theme_preview()
            
            messagebox.showinfo("成功", "自定义主题已应用！")
            
        except Exception as e:
            messagebox.showerror("错误", f"应用主题失败: {str(e)}")

    def save_settings(self):
        """保存设置"""
        try:
            import json
            
            # 保存主题设置
            theme_data = {}
            for color_key, var in self.color_vars.items():
                theme_data[color_key] = var.get()
            
            # 保存其他设置
            settings_data = {
                'theme': theme_data,
                'font_size': self.font_size_var.get(),
                'auto_save': self.auto_save_var.get(),
                'selected_theme': self.theme_var.get()
            }
            
            with open('settings.json', 'w', encoding='utf-8') as f:
                json.dump(settings_data, f, ensure_ascii=False, indent=2)
            
            messagebox.showinfo("成功", "设置已保存！")
            
        except Exception as e:
            messagebox.showerror("错误", f"保存设置失败: {str(e)}")

    def load_settings(self):
        """加载设置"""
        try:
            import json
            with open('settings.json', 'r', encoding='utf-8') as f:
                settings_data = json.load(f)
                
                # 加载主题设置
                if 'theme' in settings_data:
                    theme_data = settings_data['theme']
                    for color_key, color_value in theme_data.items():
                        if color_key in self.color_vars:
                            self.color_vars[color_key].set(color_value)
                
                # 加载其他设置
                if 'font_size' in settings_data:
                    self.font_size_var.set(settings_data['font_size'])
                if 'auto_save' in settings_data:
                    self.auto_save_var.set(settings_data['auto_save'])
                if 'selected_theme' in settings_data:
                    self.theme_var.set(settings_data['selected_theme'])
                    
        except FileNotFoundError:
            # 文件不存在，使用默认设置
            pass
        except Exception as e:
            print(f"加载设置失败: {e}")

    def create_disclaimer_ui(self):
        """创建软件声明页面"""
        # 创建主容器
        main_container = ttk.Frame(self.disclaimer_frame)
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # 标题
        title_label = ttk.Label(main_container, text="🔐 软件声明", 
                               font=('Microsoft YaHei UI', 16, 'bold'))
        title_label.pack(pady=(0, 15))
        
        # 创建文本框和滚动条
        text_frame = ttk.Frame(main_container)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        # 文本框
        self.disclaimer_text = tk.Text(text_frame, wrap=tk.WORD, font=('Microsoft YaHei UI', 10),
                                      bg=self.current_theme['bg_color'], fg=self.current_theme['fg_color'],
                                      padx=10, pady=10)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.disclaimer_text.yview)
        self.disclaimer_text.configure(yscrollcommand=scrollbar.set)
        
        # 布局
        self.disclaimer_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # 声明内容
        disclaimer_content = """🔐 文件转视频编码器/解码器 - 软件声明

⚠️ 免责声明
本软件仅供学习和研究目的使用。使用本软件所产生的任何后果，包括但不限于数据丢失、系统损坏、法律问题等，均由用户自行承担。

开发者不对以下情况承担责任：
• 因使用本软件导致的任何直接或间接损失
• 因软件缺陷或错误导致的数据损坏
• 因用户操作不当造成的任何问题
• 因第三方软件或硬件兼容性问题导致的故障

用户在使用本软件前，应当：
• 充分了解软件的功能和限制
• 备份重要数据
• 在安全环境中进行测试
• 遵守当地法律法规

📜 使用条款

1. 软件许可
本软件采用开源许可，用户可以自由使用、修改和分发，但必须遵守以下条款。

2. 禁止商用
• 严禁将本软件用于任何商业用途
• 不得将本软件作为商业产品的一部分进行销售
• 不得利用本软件进行任何形式的商业盈利活动

3. 禁止非法用途
• 严禁使用本软件进行任何违法活动
• 不得用于传播恶意软件、病毒或有害代码
• 不得用于侵犯他人知识产权
• 不得用于任何形式的网络攻击或破坏活动
• 不得用于存储或传播非法内容

4. 数据安全
• 用户应当妥善保管加密密码
• 开发者不存储用户的任何数据或密码
• 用户应当自行承担数据安全责任

5. 技术限制
• 本软件可能存在技术缺陷，不保证100%可靠
• 大文件处理可能需要较长时间
• 视频质量可能影响数据完整性

⚖️ 法律声明

1. 知识产权
本软件遵循开源协议，用户在使用过程中应当尊重知识产权。

2. 隐私保护
本软件不会收集、存储或传输用户的任何个人信息或文件内容。

3. 合规使用
用户应当确保使用本软件的行为符合当地法律法规，包括但不限于：
• 数据保护法规
• 网络安全法规
• 知识产权法规
• 反恐和国家安全法规

4. 责任限制
开发者对因用户违反本声明条款而产生的任何法律后果不承担责任。

5. 声明更新
本声明可能会不定期更新，用户应当定期查看最新版本。

📞 联系信息

如果您在使用过程中遇到问题或有任何疑问，请通过以下方式联系：

• 软件问题反馈：请通过GitHub Issues提交
• 安全漏洞报告：请通过安全渠道联系
• 法律相关问题：请咨询专业法律人士

重要提醒：
本软件仅供技术学习和研究使用，请勿用于任何违法或商业用途。
使用本软件即表示您已阅读、理解并同意遵守本声明的所有条款。

感谢您的理解和支持！"""
        
        # 插入文本内容
        self.disclaimer_text.insert(tk.END, disclaimer_content)
        self.disclaimer_text.config(state=tk.DISABLED)  # 设置为只读
        
        # 确认按钮
        confirm_frame = ttk.Frame(main_container)
        confirm_frame.pack(fill=tk.X, pady=(15, 0))
        
        ttk.Button(confirm_frame, text="✅ 我已阅读并同意以上条款", 
                  command=self.accept_disclaimer).pack()

    def accept_disclaimer(self):
        """接受声明"""
        messagebox.showinfo("确认", "感谢您的理解和支持！\n\n请记住：\n• 本软件仅供学习研究使用\n• 严禁用于商业或非法用途\n• 请遵守当地法律法规")

    def browse_encode_input(self):
        file_path = filedialog.askopenfilename(filetypes=[("所有文件", "*.*")])
        if file_path:
            self.encode_input_entry.delete(0, tk.END)
            self.encode_input_entry.insert(0, file_path)
            self.update_preview(file_path)
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            # 格式化文件大小显示
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size/1024:.2f} KB"
            elif file_size < 1024 * 1024 * 1024:
                size_str = f"{file_size/(1024*1024):.2f} MB"
            else:
                size_str = f"{file_size/(1024*1024*1024):.2f} GB"
            
            self.file_info_label.config(text=f"📄 文件: {file_name} | 📏 大小: {size_str} | ✅ 已选择")

    def browse_encode_output(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".mkv", filetypes=[("MKV files", "*.mkv")])
        if file_path:
            self.encode_output_entry.delete(0, tk.END)
            self.encode_output_entry.insert(0, file_path)

    def browse_decode_input(self):
        file_path = filedialog.askopenfilename(filetypes=[("MKV files", "*.mkv")])
        if file_path:
            self.decode_input_entry.delete(0, tk.END)
            self.decode_input_entry.insert(0, file_path)
            self.update_decode_preview(file_path)

    def browse_decode_output(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.decode_output_entry.delete(0, tk.END)
            self.decode_output_entry.insert(0, folder_path)

    def update_preview(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read(512)
            img = self.create_image_from_data(data)
            pil_img = Image.fromarray(img)
            pil_img = pil_img.resize((250, 250), Image.NEAREST)
            tk_img = ImageTk.PhotoImage(pil_img)
            self.preview_label.configure(image=tk_img, text="")
            self.preview_label.image = tk_img
            
            # 更新预览信息
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size/1024:.2f} KB"
            elif file_size < 1024 * 1024 * 1024:
                size_str = f"{file_size/(1024*1024):.2f} MB"
            else:
                size_str = f"{file_size/(1024*1024*1024):.2f} GB"
            
            self.preview_info_label.config(text=f"📄 {file_name}\n📏 {size_str}")
        except Exception as e:
            self.preview_label.configure(image="", text=f"❌ 预览失败: {str(e)}")
            self.preview_label.image = None
            self.preview_info_label.config(text="")

    def update_decode_preview(self, file_path):
        try:
            cap = cv2.VideoCapture(file_path)
            ret, frame = cap.read()
            if not ret:
                raise Exception("无法读取视频帧")
            if len(frame.shape) == 3:
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            else:
                gray = frame
            resized = cv2.resize(gray, (250, 250), interpolation=cv2.INTER_NEAREST)
            pil_img = Image.fromarray(resized)
            tk_img = ImageTk.PhotoImage(pil_img)
            self.decode_preview_label.configure(image=tk_img, text="")
            self.decode_preview_label.image = tk_img
            
            # 更新预览信息
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size/1024:.2f} KB"
            elif file_size < 1024 * 1024 * 1024:
                size_str = f"{file_size/(1024*1024):.2f} MB"
            else:
                size_str = f"{file_size/(1024*1024*1024):.2f} GB"
            
            self.decode_preview_info_label.config(text=f"🎬 {file_name}\n📏 {size_str}")
            cap.release()
        except Exception as e:
            self.decode_preview_label.configure(image="", text=f"❌ 预览失败: {str(e)}")
            self.decode_preview_label.image = None
            self.decode_preview_info_label.config(text="")

    def derive_key(self, password, salt):
        return PBKDF2(password, salt, dkLen=32, count=1000000)

    def encrypt_data(self, data, password):
        salt = get_random_bytes(16)
        iv = get_random_bytes(AES.block_size)
        key = self.derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padding_length = AES.block_size - (len(data) % AES.block_size)
        data += bytes([padding_length]) * padding_length
        encrypted_data = cipher.encrypt(data)
        return salt + iv + encrypted_data

    def decrypt_data(self, encrypted_data, password):
        salt = encrypted_data[:16]
        iv = encrypted_data[16:16 + AES.block_size]
        data = encrypted_data[16 + AES.block_size:]
        key = self.derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(data)
        padding_length = decrypted_data[-1]
        return decrypted_data[:-padding_length]

    # 新增：从数据创建图像的方法（原代码中缺失，补充完整）
    def create_image_from_data(self, data):
        resolution = self.resolution_var.get()
        width, height = map(int, resolution.split('x'))
        byte_length = width * height // 8
        if len(data) < byte_length:
            data += b'\x00' * (byte_length - len(data))
        else:
            data = data[:byte_length]
        
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        img = bits.reshape((height, width)).astype(np.uint8) * 255
        return img

    # 新增：从图像提取数据的方法（原代码中缺失，补充完整）
    def extract_data_from_image(self, frame):
        if len(frame.shape) == 3:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        else:
            gray = frame
        _, binary = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
        bits = (binary.flatten() // 255).astype(np.uint8)
        bytes_data = np.packbits(bits).tobytes()
        return bytes_data

    def encode_file_to_video(self, input_file, output_file, fps):
        try:
            resolution = self.resolution_var.get()
            width, height = map(int, resolution.split('x'))
            if width <= 0 or height <= 0:
                raise ValueError("尺寸必须大于0")

            # 获取密码（可选）
            password = self.encode_password_entry.get().strip()
            is_encrypted = 1 if password else 0  # 加密标志：1=加密，0=不加密

            file_name = os.path.basename(input_file)
            file_name_bytes = file_name.encode('utf-8')
            with open(input_file, 'rb') as f:
                file_data = f.read()

            # 计算原始数据哈希（无论是否加密都基于原始数据）
            data_hash = hashlib.sha256(file_data).digest()

            # 根据密码决定是否加密
            if is_encrypted:
                processed_data = self.encrypt_data(file_data, password)
            else:
                processed_data = file_data  # 不加密，直接使用原始数据

            # 数据结构：[加密标志(1字节)] + [哈希(32字节)] + [文件名长度(4字节)] + [文件名] + [数据长度(8字节)] + [数据]
            encrypted_flag = is_encrypted.to_bytes(1, byteorder='big')
            file_name_len = len(file_name_bytes).to_bytes(4, byteorder='big')
            data_len = len(processed_data).to_bytes(8, byteorder='big')
            final_data = encrypted_flag + data_hash + file_name_len + file_name_bytes + data_len + processed_data

            bytes_per_frame = (width * height) // 8
            frame_header_size = 16  # 帧头长度为16字节
            effective_bytes_per_frame = bytes_per_frame - frame_header_size

            total_bytes = len(final_data)
            total_frames = (total_bytes + effective_bytes_per_frame - 1) // effective_bytes_per_frame

            fourcc = cv2.VideoWriter_fourcc(*'FFV1')
            out = cv2.VideoWriter(output_file, fourcc, fps, (width, height), isColor=False)
            if not out.isOpened():
                raise Exception("无法创建视频文件，请确保已安装支持FFV1编码的FFmpeg")

            self.encode_start_time = time.time()
            self.encode_processed_bytes = 0
            last_updated_time = self.encode_start_time
            update_interval = 1

            for frame_idx in range(total_frames):
                start = frame_idx * effective_bytes_per_frame
                end = min(start + effective_bytes_per_frame, total_bytes)
                current_data = final_data[start:end]
                current_data_len = len(current_data)

                self.encode_processed_bytes += current_data_len

                frame_header = current_data_len.to_bytes(16, byteorder='big')
                frame_full_data = frame_header + current_data

                if len(frame_full_data) < bytes_per_frame:
                    frame_full_data += b'\x00' * (bytes_per_frame - len(frame_full_data))

                img = self.create_image_from_data(frame_full_data)
                out.write(img)

                current_time = time.time()
                if current_time - last_updated_time >= update_interval or frame_idx == total_frames - 1:
                    elapsed_time = current_time - self.encode_start_time
                    if elapsed_time > 0:
                        speed_mb_per_sec = (self.encode_processed_bytes / (1024 * 1024)) / elapsed_time
                        progress_text = f"处理速度: {speed_mb_per_sec:.2f} MB/s | 已处理: {frame_idx + 1}/{total_frames} 帧"
                        self.root.after(0, lambda t=progress_text: 
                                       self.encode_speed_label.config(text=t))
                    last_updated_time = current_time

                progress = (frame_idx + 1) / total_frames * 100
                self.encode_progress['value'] = progress
                self.root.update_idletasks()

            out.release()
            status = "🔐 加密编码" if is_encrypted else "🔓 无加密编码"
            messagebox.showinfo("✅ 编码成功", f"{status}完成！\n\n📊 统计信息:\n• 创建了 {total_frames} 帧视频\n• 包含数据和校验信息\n• 文件已保存到指定位置")
        except Exception as e:
            messagebox.showerror("错误", f"编码失败: {str(e)}")
        finally:
            self.root.after(0, lambda: self.encode_speed_label.config(text="处理速度: -- MB/s"))
            self.encoding = False
            self.encode_button.config(state=tk.NORMAL, text="🚀 开始编码")
            self.encode_progress['value'] = 0

    def decode_video_to_file(self, input_file, output_folder):
        try:
            cap = cv2.VideoCapture(input_file)
            if not cap.isOpened():
                raise Exception("无法打开视频文件")

            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            if total_frames == 0:
                raise Exception("视频中没有帧")

            # 获取密码（可选）
            password = self.decode_password_entry.get().strip()

            all_bytes = bytearray()
            
            self.decode_start_time = time.time()
            self.decode_processed_bytes = 0
            last_updated_time = self.decode_start_time
            update_interval = 1

            for frame_idx in range(total_frames):
                ret, frame = cap.read()
                if not ret:
                    break

                frame_bytes = self.extract_data_from_image(frame)
                if len(frame_bytes) < 16:
                    raise Exception(f"帧 {frame_idx} 数据不完整")
                
                current_data_len = int.from_bytes(frame_bytes[:16], byteorder='big')
                if current_data_len > 0:
                    frame_data = frame_bytes[16:16+current_data_len]
                    all_bytes.extend(frame_data)
                    self.decode_processed_bytes += len(frame_data)

                current_time = time.time()
                if current_time - last_updated_time >= update_interval or frame_idx == total_frames - 1:
                    elapsed_time = current_time - self.decode_start_time
                    if elapsed_time > 0:
                        speed_mb_per_sec = (self.decode_processed_bytes / (1024 * 1024)) / elapsed_time
                        progress_text = f"处理速度: {speed_mb_per_sec:.2f} MB/s | 已处理: {frame_idx + 1}/{total_frames} 帧"
                        self.root.update_idletasks()
                        self.root.after(0, lambda t=progress_text: 
                                       self.decode_speed_label.config(text=t))
                    last_updated_time = current_time

                progress = (frame_idx + 1) / total_frames * 100
                self.decode_progress['value'] = progress
                self.root.update_idletasks()

            cap.release()

            # 解析数据结构：[加密标志(1字节)] + [哈希(32字节)] + [文件名长度(4字节)] + [文件名] + [数据长度(8字节)] + [数据]
            if len(all_bytes) < 1 + 32 + 4 + 8:
                raise Exception("数据不完整，无法解析")

            # 读取加密标志
            is_encrypted = all_bytes[0]
            ptr = 1

            # 读取哈希
            data_hash = all_bytes[ptr:ptr+32]
            ptr += 32

            # 读取文件名
            file_name_len = int.from_bytes(all_bytes[ptr:ptr+4], byteorder='big')
            ptr += 4
            if ptr + file_name_len > len(all_bytes):
                raise Exception("文件名数据不完整")
            file_name_bytes = all_bytes[ptr:ptr+file_name_len]
            ptr += file_name_len
            file_name = file_name_bytes.decode('utf-8')

            # 读取数据
            data_len = int.from_bytes(all_bytes[ptr:ptr+8], byteorder='big')
            ptr += 8
            if ptr + data_len > len(all_bytes):
                raise Exception("文件数据不完整")
            processed_data = all_bytes[ptr:ptr+data_len]

            # 根据加密标志决定是否解密
            if is_encrypted:
                if not password:
                    raise Exception("该视频已加密，请输入解密密码")
                try:
                    file_data = self.decrypt_data(processed_data, password)
                except Exception as e:
                    raise Exception(f"解密失败，可能是密码错误: {str(e)}")
            else:
                if password:
                    messagebox.showwarning("提示", "该视频未加密，密码将被忽略")
                file_data = processed_data  # 不加密，直接使用原始数据

            # 验证哈希
            computed_hash = hashlib.sha256(file_data).digest()
            if computed_hash != data_hash:
                raise Exception("数据损坏或被篡改，哈希校验失败")

            output_path = os.path.join(output_folder, file_name)
            if os.path.exists(output_path):
                if not messagebox.askyesno("确认", f"文件 {file_name} 已存在，是否覆盖?"):
                    return

            with open(output_path, 'wb') as f:
                f.write(file_data)

            status = "🔐 加密解码" if is_encrypted else "🔓 无加密解码"
            messagebox.showinfo("✅ 解码成功", f"{status}完成！\n\n📊 统计信息:\n• 已还原文件: {file_name}\n• 保存路径: {output_folder}\n• ✅ 数据校验通过")
        except Exception as e:
            messagebox.showerror("错误", f"解码失败: {str(e)}")
        finally:
            self.root.after(0, lambda: self.decode_speed_label.config(text="处理速度: -- MB/s"))
            self.decoding = False
            self.decode_button.config(state=tk.NORMAL, text="🚀 开始解码")
            self.decode_progress['value'] = 0

    def start_encoding(self):
        input_file = self.encode_input_entry.get()
        output_file = self.encode_output_entry.get()
        
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("错误", "请选择有效的输入文件")
            return
            
        if not output_file:
            messagebox.showerror("错误", "请选择输出视频路径")
            return
            
        try:
            fps = float(self.fps_var.get())
            if fps <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("错误", "请输入有效的帧率")
            return
            
        self.encoding = True
        self.encode_button.config(state=tk.DISABLED, text="⏳ 编码中...")
        threading.Thread(target=self.encode_file_to_video, args=(input_file, output_file, fps), daemon=True).start()

    def start_decoding(self):
        input_file = self.decode_input_entry.get()
        output_folder = self.decode_output_entry.get()
        
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("错误", "请选择有效的视频文件")
            return
            
        if not output_folder or not os.path.isdir(output_folder):
            messagebox.showerror("错误", "请选择有效的输出文件夹")
            return
            
        self.decoding = True
        self.decode_button.config(state=tk.DISABLED, text="⏳ 解码中...")
        threading.Thread(target=self.decode_video_to_file, args=(input_file, output_folder), daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileToVideoConverter(root)
    root.mainloop()