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

class FileToVideoConverter:
    def __init__(self, root):
        self.root = root
        self.root.title("文件转视频编码器/解码器(加密可选)")
        self.root.geometry("800x750")
        self.root.resizable(True, True)
        
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.encode_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encode_frame, text="编码")
        
        self.decode_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decode_frame, text="解码")
        
        self.create_encode_ui()
        self.create_decode_ui()
        
        self.encoding = False
        self.decoding = False
        
        self.encode_start_time = 0
        self.encode_processed_bytes = 0
        self.decode_start_time = 0
        self.decode_processed_bytes = 0

    def create_encode_ui(self):
        ttk.Label(self.encode_frame, text="输入文件:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.encode_input_entry = ttk.Entry(self.encode_frame, width=50)
        self.encode_input_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(self.encode_frame, text="浏览...", command=self.browse_encode_input).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(self.encode_frame, text="输出视频:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.encode_output_entry = ttk.Entry(self.encode_frame, width=50)
        self.encode_output_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(self.encode_frame, text="浏览...", command=self.browse_encode_output).grid(row=1, column=2, padx=5, pady=5)
        
        # 修改密码输入框提示为可选
        ttk.Label(self.encode_frame, text="加密密码 (可选):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.encode_password_entry = ttk.Entry(self.encode_frame, show="*", width=30)
        self.encode_password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(self.encode_frame, text="不填则不加密").grid(row=2, column=2, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(self.encode_frame, text="帧率 (fps):").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.fps_var = tk.StringVar(value="10")
        ttk.Entry(self.encode_frame, textvariable=self.fps_var, width=10).grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(self.encode_frame, text="图像尺寸:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.resolution_var = tk.StringVar(value="256x256")
        resolutions = ["128x128", "256x256", "512x512", "1024x1024", "2048x2048", "4096x4096"]
        self.resolution_combo = ttk.Combobox(
            self.encode_frame, 
            textvariable=self.resolution_var, 
            values=resolutions,
            state="readonly",
            width=10
        )
        self.resolution_combo.grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        
        self.file_info_label = ttk.Label(self.encode_frame, text="")
        self.file_info_label.grid(row=5, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(self.encode_frame, text="预览:").grid(row=6, column=0, padx=5, pady=5, sticky=tk.W)
        self.preview_label = ttk.Label(self.encode_frame)
        self.preview_label.grid(row=7, column=0, columnspan=3, padx=5, pady=5)
        
        self.encode_progress = ttk.Progressbar(self.encode_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.encode_progress.grid(row=8, column=0, columnspan=3, sticky=tk.EW, padx=5, pady=10)
        
        self.encode_speed_label = ttk.Label(self.encode_frame, text="处理速度: -- MB/s")
        self.encode_speed_label.grid(row=9, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        self.encode_button = ttk.Button(self.encode_frame, text="开始编码", command=self.start_encoding)
        self.encode_button.grid(row=10, column=0, columnspan=3, pady=10)
        
        self.encode_frame.columnconfigure(1, weight=1)

    def create_decode_ui(self):
        ttk.Label(self.decode_frame, text="视频文件:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.decode_input_entry = ttk.Entry(self.decode_frame, width=50)
        self.decode_input_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(self.decode_frame, text="浏览...", command=self.browse_decode_input).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(self.decode_frame, text="输出文件夹:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.decode_output_entry = ttk.Entry(self.decode_frame, width=50)
        self.decode_output_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        ttk.Button(self.decode_frame, text="浏览...", command=self.browse_decode_output).grid(row=1, column=2, padx=5, pady=5)
        
        # 修改密码输入框提示为可选
        ttk.Label(self.decode_frame, text="解密密码 (可选):").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.decode_password_entry = ttk.Entry(self.decode_frame, show="*", width=30)
        self.decode_password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(self.decode_frame, text="加密时填写的密码").grid(row=2, column=2, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(self.decode_frame, text="预览:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.decode_preview_label = ttk.Label(self.decode_frame)
        self.decode_preview_label.grid(row=4, column=0, columnspan=3, padx=5, pady=5)
        
        self.decode_progress = ttk.Progressbar(self.decode_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.decode_progress.grid(row=5, column=0, columnspan=3, sticky=tk.EW, padx=5, pady=10)
        
        self.decode_speed_label = ttk.Label(self.decode_frame, text="处理速度: -- MB/s")
        self.decode_speed_label.grid(row=6, column=0, columnspan=3, padx=5, pady=5, sticky=tk.W)
        
        self.decode_button = ttk.Button(self.decode_frame, text="开始解码", command=self.start_decoding)
        self.decode_button.grid(row=7, column=0, columnspan=3, pady=10)
        
        self.decode_frame.columnconfigure(1, weight=1)

    def browse_encode_input(self):
        file_path = filedialog.askopenfilename(filetypes=[("所有文件", "*.*")])
        if file_path:
            self.encode_input_entry.delete(0, tk.END)
            self.encode_input_entry.insert(0, file_path)
            self.update_preview(file_path)
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            self.file_info_label.config(text=f"文件: {file_name} | 大小: {file_size} 字节 ({file_size/1024:.2f} KB)")

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
            pil_img = pil_img.resize((256, 256), Image.NEAREST)
            tk_img = ImageTk.PhotoImage(pil_img)
            self.preview_label.configure(image=tk_img)
            self.preview_label.image = tk_img
        except Exception as e:
            messagebox.showerror("错误", f"预览失败: {str(e)}")

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
            resized = cv2.resize(gray, (256, 256), interpolation=cv2.INTER_NEAREST)
            pil_img = Image.fromarray(resized)
            tk_img = ImageTk.PhotoImage(pil_img)
            self.decode_preview_label.configure(image=tk_img)
            self.decode_preview_label.image = tk_img
            cap.release()
        except Exception as e:
            messagebox.showerror("错误", f"预览失败: {str(e)}")

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
                        self.root.after(0, lambda s=speed_mb_per_sec: 
                                       self.encode_speed_label.config(text=f"处理速度: {s:.2f} MB/s"))
                    last_updated_time = current_time

                progress = (frame_idx + 1) / total_frames * 100
                self.encode_progress['value'] = progress
                self.root.update_idletasks()

            out.release()
            status = "加密编码" if is_encrypted else "无加密编码"
            messagebox.showinfo("成功", f"{status}完成！\n创建了 {total_frames} 帧视频，包含数据和校验信息")
        except Exception as e:
            messagebox.showerror("错误", f"编码失败: {str(e)}")
        finally:
            self.root.after(0, lambda: self.encode_speed_label.config(text="处理速度: -- MB/s"))
            self.encoding = False
            self.encode_button.config(state=tk.NORMAL)
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
                        self.root.update_idletasks()
                        self.root.after(0, lambda s=speed_mb_per_sec: 
                                       self.decode_speed_label.config(text=f"处理速度: {s:.2f} MB/s"))
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

            status = "加密解码" if is_encrypted else "无加密解码"
            messagebox.showinfo("成功", f"{status}完成！\n已还原文件: {file_name}\n保存路径: {output_folder}\n数据校验通过")
        except Exception as e:
            messagebox.showerror("错误", f"解码失败: {str(e)}")
        finally:
            self.root.after(0, lambda: self.decode_speed_label.config(text="处理速度: -- MB/s"))
            self.decoding = False
            self.decode_button.config(state=tk.NORMAL)
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
        self.encode_button.config(state=tk.DISABLED)
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
        self.decode_button.config(state=tk.DISABLED)
        threading.Thread(target=self.decode_video_to_file, args=(input_file, output_folder), daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = FileToVideoConverter(root)
    root.mainloop()